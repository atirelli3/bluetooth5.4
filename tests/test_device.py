"""BTDevice: P-256 key pair, ECDH with peer-key checks, random static address."""

import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from bt54.device import (
    BTDevice,
    InvalidPublicKey,
    load_public_key,
    random_static_address,
)

P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1


def test_both_sides_derive_the_same_32_octet_dhkey():
    alice, bob = BTDevice(), BTDevice()
    shared = alice.compute_dh_key(bob.pK)
    assert shared == bob.compute_dh_key(alice.pK) == alice.dhkey
    assert len(shared) == 32


def test_dhkey_depends_on_the_peer():
    alice = BTDevice()
    assert alice.compute_dh_key(BTDevice().pK) != alice.compute_dh_key(BTDevice().pK)


def test_a_peer_with_our_x_coordinate_is_rejected():
    """Vol 3 Part H §2.3.5.6.1: same X (here the negated point, Y' = p - Y) → fail the pairing."""
    alice = BTDevice()
    y = alice.pK.public_numbers().y
    mirror = ec.EllipticCurvePublicNumbers(alice.pK_x, P256_P - y, ec.SECP256R1())
    with pytest.raises(InvalidPublicKey, match="same X"):
        alice.compute_dh_key(mirror.public_key())


def test_a_rejected_peer_leaves_no_stale_dhkey():
    alice = BTDevice()
    alice.compute_dh_key(BTDevice().pK)
    with pytest.raises(InvalidPublicKey):
        alice.compute_dh_key(alice.pK)
    assert alice.dhkey is None


def test_load_public_key_round_trips_a_valid_key():
    numbers = BTDevice().pK.public_numbers()
    x, y = numbers.x.to_bytes(32, "big"), numbers.y.to_bytes(32, "big")
    assert load_public_key(x, y).public_numbers() == numbers


def test_an_off_curve_point_is_rejected():
    """CVE-2018-5383: a received public key must lie on P-256."""
    x = BTDevice().pK_x.to_bytes(32, "big")
    with pytest.raises(InvalidPublicKey, match="not on P-256"):
        load_public_key(x, bytes(31) + b"\x01")


def test_load_public_key_rejects_wrong_lengths():
    with pytest.raises(ValueError, match="32 octets") as excinfo:
        load_public_key(bytes(31), bytes(32))
    assert not isinstance(excinfo.value, InvalidPublicKey)


def test_random_static_address_sets_the_two_most_significant_bits(monkeypatch):
    """Vol 6 Part B §1.3.2.1: 6 octets, the two most significant bits are 0b11."""
    monkeypatch.setattr(secrets, "token_bytes", lambda _: b"\x01" + bytes(5))
    assert random_static_address() == b"\xc1" + bytes(5)


def test_random_static_address_redraws_an_all_zero_or_all_one_random_part(monkeypatch):
    draws = iter([bytes(6), b"\xff" * 6, bytes.fromhex("c00000000001")])
    monkeypatch.setattr(secrets, "token_bytes", lambda _: next(draws))
    assert random_static_address() == bytes.fromhex("c00000000001")


def test_pairing_address_is_the_type_octet_then_the_address():
    """A1/A2 of f5 and f6 (Vol 3 Part H §2.2.7), as in Appendix D.3."""
    device = BTDevice(address=bytes.fromhex("56123737bfce"), address_type=0)
    assert device.pairing_address == bytes.fromhex("0056123737bfce")


def test_default_address_is_random_static():
    device = BTDevice()
    assert device.pairing_address[0] == 1
    assert device.pairing_address[1] >> 6 == 0b11


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        pytest.param({"address": bytes(5)}, "address must be 6", id="5-octet-address"),
        pytest.param(
            {"address": bytes(6), "address_type": 2},
            "address_type must be 0 or 1",
            id="type-2",
        ),
        pytest.param(
            {"address_type": 0},
            "address_type must be 1",
            id="generated-address-as-public",
        ),
    ],
)
def test_bad_address_arguments_are_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        BTDevice(**kwargs)

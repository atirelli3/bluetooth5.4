"""LE Secure Connections pairing (Core v5.4 Vol 3 Part H §2.3.5.6, §3.5): key size, stage 1, stage 2, failures."""

from dataclasses import replace

import pytest

from bt54 import pairing
from bt54.device import AuthReq, BTDevice, InvalidPublicKey, IOCap
from bt54.pairing import (
    PairingFailed,
    Reason,
    authenticate,
    check_commit,
    exchange,
    mask_key,
)
from bt54.toolbox import f4, f5, f6, g2


def pair(central_size: int = 16, peripheral_size: int = 16):
    return exchange(
        BTDevice(max_key_size=central_size), BTDevice(max_key_size=peripheral_size)
    )


@pytest.mark.parametrize(
    ("flag", "mask"),
    [
        pytest.param(AuthReq.BONDING, 0x01, id="Bonding_Flags-b0"),
        pytest.param(AuthReq.MITM, 0x04, id="MITM-b2"),
        pytest.param(AuthReq.SC, 0x08, id="SC-b3"),
        pytest.param(AuthReq.KEYPRESS, 0x10, id="Keypress-b4"),
        pytest.param(AuthReq.CT2, 0x20, id="CT2-b5"),
    ],
)
def test_auth_req_bits(flag, mask):
    """Vol 3 Part H §3.5.1 Figure 3.3, read from the spec's image: LSB first Bonding_Flags (2), MITM, SC, Keypress, CT2, RFU (2)."""
    assert flag == mask


@pytest.mark.parametrize(
    ("capability", "value"),
    [
        pytest.param(IOCap.DISPLAY_ONLY, 0, id="DisplayOnly"),
        pytest.param(IOCap.DISPLAY_YES_NO, 1, id="DisplayYesNo"),
        pytest.param(IOCap.KEYBOARD_ONLY, 2, id="KeyboardOnly"),
        pytest.param(IOCap.NO_INPUT_NO_OUTPUT, 3, id="NoInputNoOutput"),
        pytest.param(IOCap.KEYBOARD_DISPLAY, 4, id="KeyboardDisplay"),
    ],
)
def test_io_capability_values(capability, value):
    """Vol 3 Part H §3.5.1 Table 3.4."""
    assert capability == value


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        pytest.param(Reason.CONFIRM_VALUE_FAILED, 0x04, id="confirm-value"),
        pytest.param(Reason.ENCRYPTION_KEY_SIZE, 0x06, id="key-size"),
        pytest.param(Reason.DHKEY_CHECK_FAILED, 0x0B, id="dhkey-check"),
        pytest.param(Reason.NUMERIC_COMPARISON_FAILED, 0x0C, id="numeric-comparison"),
    ],
)
def test_pairing_failed_reason_codes(reason, code):
    """Vol 3 Part H §3.5.5 Table 3.7."""
    assert reason == code
    assert PairingFailed(reason).reason is reason


def test_mask_key_matches_the_spec_example():
    """Vol 3 Part H §2.3.4: 12345678_9ABCDEF0_12345678_9ABCDEF0 reduced to 7 octets."""
    key = bytes.fromhex("12345678 9ABCDEF0 12345678 9ABCDEF0")
    assert mask_key(key, 7) == bytes.fromhex("00000000 00000000 00345678 9ABCDEF0")


@pytest.mark.parametrize("size", [1, 7, 15, 16])
def test_mask_key_keeps_the_least_significant_octets(size):
    key = bytes(range(1, 17))
    masked = mask_key(key, size)
    assert masked == bytes(16 - size) + key[16 - size :]
    assert len(masked) == 16


@pytest.mark.parametrize(
    ("key", "size"),
    [
        pytest.param(bytes(15), 7, id="key-15-octets"),
        pytest.param(bytes(16), 0, id="size-0"),
        pytest.param(bytes(16), 17, id="size-17"),
    ],
)
def test_mask_key_rejects_bad_input(key, size):
    with pytest.raises(ValueError, match="must be"):
        mask_key(key, size)


@pytest.mark.parametrize("size", [0, 17])
def test_a_device_rejects_a_max_key_size_outside_1_to_16(size):
    with pytest.raises(ValueError, match="max_key_size"):
        BTDevice(max_key_size=size)


def test_a_device_defaults_to_bonding_and_secure_connections_with_16_octets():
    device = BTDevice()
    assert device.auth_req == AuthReq.BONDING | AuthReq.SC
    assert device.max_key_size == 16


def test_an_honest_exchange_gives_both_sides_the_same_dhkey_and_a_six_digit_number():
    x = pair()
    assert x.dhkey_c == x.dhkey_p
    assert len(x.dhkey_c) == 32
    assert 0 <= x.number < 10**6
    assert len(x.na) == len(x.nb) == 16
    assert x.na != x.nb


def test_the_number_is_g2_mod_10_to_the_6():
    """Vol 3 Part H §2.2.9: g2(PKax, PKbx, Na, Nb) mod 10^6."""
    x = pair()
    pk_a, pk_b = (d.pK_x.to_bytes(32) for d in (x.central, x.peripheral))
    assert x.number == g2(pk_a, pk_b, x.na, x.nb) % 10**6


@pytest.mark.parametrize(
    ("central_flags", "peripheral_flags"),
    [
        pytest.param(AuthReq.BONDING, AuthReq.SC, id="central-lacks-SC"),
        pytest.param(AuthReq.SC, AuthReq.BONDING, id="peripheral-lacks-SC"),
    ],
)
def test_both_devices_must_set_sc(central_flags, peripheral_flags):
    """Vol 3 Part H §2.3.1: without SC on both sides the pairing is legacy, which bt54 does not simulate."""
    with pytest.raises(ValueError, match="SC flag"):
        exchange(BTDevice(auth_req=central_flags), BTDevice(auth_req=peripheral_flags))


def test_two_exchanges_share_nothing():
    first, second = pair(), pair()
    assert (first.na, first.nb, first.dhkey_c) != (second.na, second.nb, second.dhkey_c)


@pytest.mark.parametrize(
    ("central_size", "peripheral_size", "key_size"),
    [
        pytest.param(16, 16, 16, id="both-16"),
        pytest.param(16, 10, 10, id="shorter-wins-peripheral"),
        pytest.param(9, 16, 9, id="shorter-wins-central"),
        pytest.param(7, 7, 7, id="floor-accepted"),
    ],
)
def test_the_key_size_is_the_shorter_maximum(central_size, peripheral_size, key_size):
    """Vol 3 Part H §2.3.4: the shorter of the two maximum encryption key lengths."""
    assert pair(central_size, peripheral_size).key_size == key_size


@pytest.mark.parametrize(
    ("central_size", "peripheral_size"),
    [
        pytest.param(6, 16, id="central-offers-6"),
        pytest.param(16, 6, id="peripheral-offers-6"),
        pytest.param(1, 1, id="both-offer-1"),
    ],
)
def test_a_key_size_below_7_fails_the_pairing(central_size, peripheral_size):
    """Vol 3 Part H §2.3.4: the minimum is 7 octets; Pairing Failed with 'Encryption Key Size'."""
    with pytest.raises(PairingFailed) as failed:
        pair(central_size, peripheral_size)
    assert failed.value.reason is Reason.ENCRYPTION_KEY_SIZE


def test_a_peer_with_our_x_coordinate_fails_the_exchange():
    alice = BTDevice()
    with pytest.raises(InvalidPublicKey, match="same X"):
        exchange(alice, alice)


def test_the_commit_check_accepts_the_real_nonce_and_rejects_another():
    """Vol 3 Part H §2.3.5.6.2: Cb = f4(PKbx, PKax, Nb, 0), checked by the initiator."""
    x = pair()
    pk_a, pk_b = (d.pK_x.to_bytes(32) for d in (x.central, x.peripheral))
    commit = f4(pk_b, pk_a, x.nb, bytes(1))
    check_commit(commit, pk_a, pk_b, x.nb)
    with pytest.raises(PairingFailed) as failed:
        check_commit(commit, pk_a, pk_b, bytes(16))
    assert failed.value.reason is Reason.CONFIRM_VALUE_FAILED


def test_exchange_runs_the_commit_check(monkeypatch):
    """The initiator's check (f4 call 2) is wired into the exchange: a wrong Cb aborts it."""
    calls = []

    def corrupt_the_check(*args):
        calls.append(args)
        return bytes(16) if len(calls) == 2 else f4(*args)

    monkeypatch.setattr(pairing, "f4", corrupt_the_check)
    with pytest.raises(PairingFailed) as failed:
        pair()
    assert failed.value.reason is Reason.CONFIRM_VALUE_FAILED


def test_authenticate_feeds_f6_the_spec_arguments(monkeypatch):
    """§2.3.5.6.5: Ea = f6(MacKey, Na, Nb, 0, IOcapA, A, B), Eb = f6(MacKey, Nb, Na, 0, IOcapB, B, A)."""
    central = BTDevice(
        iocap=IOCap.DISPLAY_YES_NO,
        auth_req=AuthReq.BONDING | AuthReq.MITM | AuthReq.SC,
    )
    peripheral = BTDevice(
        iocap=IOCap.NO_INPUT_NO_OUTPUT, auth_req=AuthReq.BONDING | AuthReq.SC
    )
    x = exchange(central, peripheral)
    a, b = central.pairing_address, peripheral.pairing_address
    mac_key, _ = f5(x.dhkey_c, x.na, x.nb, a, b)
    calls = []

    def spy(*args):
        calls.append(args)
        return f6(*args)

    monkeypatch.setattr(pairing, "f6", spy)
    authenticate(x)
    assert calls[0] == (mac_key, x.na, x.nb, bytes(16), bytes([0x0D, 0, 1]), a, b)
    assert calls[2] == (mac_key, x.nb, x.na, bytes(16), bytes([0x09, 0, 3]), b, a)


def test_authenticate_returns_the_f5_ltk_of_both_sides():
    """Vol 3 Part H §2.2.7: MacKey || LTK = f5(DHKey, Na, Nb, A, B), A = central, B = peripheral."""
    x = pair()
    _, ltk = f5(
        x.dhkey_c,
        x.na,
        x.nb,
        x.central.pairing_address,
        x.peripheral.pairing_address,
    )
    assert authenticate(x) == ltk


@pytest.mark.parametrize("key_size", [7, 10, 16])
def test_the_ltk_is_masked_to_the_negotiated_key_size(key_size):
    """Vol 3 Part H §2.3.4 and §2.4.4.2: the LTK is shortened to the agreed size."""
    ltk = authenticate(pair(key_size, 16))
    assert ltk[: 16 - key_size] == bytes(16 - key_size)
    assert any(ltk[16 - key_size :])


@pytest.mark.parametrize(
    "bad_call",
    [
        pytest.param(2, id="responder-checks-Ea"),
        pytest.param(4, id="initiator-checks-Eb"),
    ],
)
def test_a_wrong_check_value_fails_in_either_direction(monkeypatch, bad_call):
    """Vol 3 Part H §2.3.5.6.5: Ea is checked by the responder (f6 call 2), then Eb by the initiator (call 4)."""
    calls = []

    def corrupt_one(*args):
        calls.append(args)
        return bytes(16) if len(calls) == bad_call else f6(*args)

    monkeypatch.setattr(pairing, "f6", corrupt_one)
    with pytest.raises(PairingFailed) as failed:
        authenticate(pair())
    assert failed.value.reason is Reason.DHKEY_CHECK_FAILED
    assert len(calls) == bad_call


@pytest.mark.parametrize("field", ["dhkey_c", "dhkey_p"])
def test_a_different_dhkey_on_either_side_fails_the_dhkey_check(field):
    """Vol 3 Part H §2.3.5.6.5: the f6 check values differ when the two MacKeys differ."""
    x = pair()
    with pytest.raises(PairingFailed) as failed:
        authenticate(replace(x, **{field: bytes(32)}))
    assert failed.value.reason is Reason.DHKEY_CHECK_FAILED

"""Encrypted Advertising Data (CSS v11 Part A §1.23) against the spec's sample data and tamper/length checks."""

import pytest

from bt54 import ccm, ead

KEY = bytes.fromhex("57A9DA12D12E6E131E20612AD10A6A19")
IV = bytes.fromhex("46E77AB1EF007A9E")
PAYLOAD = bytes.fromhex("0f0953686f7274204d696e692d42757303190a8c")


@pytest.mark.parametrize(
    ("randomizer", "ad_data"),
    [
        pytest.param(
            bytes.fromhex("18E157CADE"),
            "18E157CADE 74E4DCAFDC51C7282810C2217F0E4CEF4343181F BA0069CC",
            id="set-1",
        ),
        pytest.param(
            bytes.fromhex("8D1C976E7A"),
            "8D1C976E7A 35444076125788C238A58E8BD9CFF0DEFE251A8E 7275454C",
            id="set-2-same-payload-new-randomizer",
        ),
    ],
)
def test_matches_the_css_sample_data(randomizer, ad_data):
    """CSS v11 Part A §2.3.1 and §2.3.2: Randomizer (5, on air LSO-first) || encrypted payload || MIC (4)."""
    data = bytes.fromhex(ad_data)
    assert ead.decrypt(KEY, IV, data) == PAYLOAD
    assert ead.encrypt(KEY, IV, PAYLOAD, randomizer=randomizer) == data


def test_a_random_randomizer_is_5_octets_and_round_trips():
    data = ead.encrypt(KEY, IV, PAYLOAD)
    assert len(data) == 5 + len(PAYLOAD) + 4
    assert ead.decrypt(KEY, IV, data) == PAYLOAD


def test_two_calls_draw_different_randomizers():
    first, second = ead.encrypt(KEY, IV, PAYLOAD), ead.encrypt(KEY, IV, PAYLOAD)
    assert first[:5] != second[:5]


@pytest.mark.parametrize("size", [4, 6])
def test_encrypt_rejects_a_randomizer_that_is_not_5_octets(size):
    with pytest.raises(ValueError, match="5 octets"):
        ead.encrypt(KEY, IV, PAYLOAD, randomizer=bytes(size))


@pytest.mark.parametrize("size", range(9))
def test_decrypt_rejects_data_shorter_than_randomizer_plus_mic(size):
    with pytest.raises(ValueError, match="9 octets"):
        ead.decrypt(KEY, IV, bytes(size))


@pytest.mark.parametrize("index", [0, 4, 9, -1])
def test_a_tampered_octet_fails_the_mic(index):
    data = bytearray(ead.encrypt(KEY, IV, PAYLOAD))
    data[index] ^= 0xFF
    with pytest.raises(ccm.InvalidTag):
        ead.decrypt(KEY, IV, bytes(data))


def test_the_wrong_key_fails_the_mic():
    data = ead.encrypt(KEY, IV, PAYLOAD)
    with pytest.raises(ccm.InvalidTag):
        ead.decrypt(bytes(16), IV, data)

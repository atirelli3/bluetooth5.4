"""Hand-rolled AES-CCM against the LE sample data (Core v5.4 Vol 6 Part C §1) and cryptography's AESCCM."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from bt54 import ccm

SK = bytes.fromhex("99ad1b5226a37e3e058e3b8e27c2c666")
NONCE = bytes.fromhex("000000008024abdcbabebaafde")


@pytest.mark.parametrize(
    ("nonce", "header", "payload", "sealed"),
    [
        pytest.param(
            "000000008024abdcbabebaafde",
            "03",
            "06",
            "9f cda7f448",
            id="LL_START_ENC_RSP1",
        ),
        pytest.param(
            "000000000024abdcbabebaafde",
            "03",
            "06",
            "a3 4c13a415",
            id="LL_START_ENC_RSP2",
        ),
        pytest.param(
            "010000008024abdcbabebaafde",
            "02",
            "1700636465666768696a6b6c6d6e6f707131323334353637383930",
            "7a70d66415226df26b17839a060405596bd6564f796b5b9ce6ff32 f75a6d33",
            id="LL_DATA1",
        ),
        pytest.param(
            "010000000024abdcbabebaafde",
            "02",
            "17003736353433323130414243444546474849 4a4b4c4d4e4f5051",
            "f38881e7bd94c9c369b9a66846dd4786aa8c39ce540d0dae3adcdf 89b96088",
            id="LL_DATA2",
        ),
    ],
)
def test_ccm_matches_le_sample_data(nonce, header, payload, sealed):
    nonce, aad, plaintext, sealed = (
        bytes.fromhex(x.replace(" ", "")) for x in (nonce, header, payload, sealed)
    )
    assert ccm.encrypt(SK, nonce, plaintext, aad) == sealed
    assert ccm.decrypt(SK, nonce, sealed, aad) == plaintext


IV = bytes.fromhex("DEAFBABEBADCAB24")
CENTRAL, PERIPHERAL = 1, 0


@pytest.mark.parametrize(
    ("counter", "direction", "nonce"),
    [
        pytest.param(0, CENTRAL, "000000008024abdcbabebaafde", id="counter0-central"),
        pytest.param(
            0, PERIPHERAL, "000000000024abdcbabebaafde", id="counter0-peripheral"
        ),
        pytest.param(1, CENTRAL, "010000008024abdcbabebaafde", id="counter1-central"),
        pytest.param(
            1, PERIPHERAL, "010000000024abdcbabebaafde", id="counter1-peripheral"
        ),
        pytest.param(
            (1 << 39) - 1, PERIPHERAL, "ffffffff7f24abdcbabebaafde", id="counter-max"
        ),
        pytest.param(
            0x0102030405, CENTRAL, "0504030281" + "24abdcbabebaafde", id="octet-order"
        ),
    ],
)
def test_ll_nonce_matches_le_sample_data(counter, direction, nonce):
    """Vol 6 Part E Table 2.1: packetCounter LSO first, directionBit = bit 7 of Nonce4, IV LSO first."""
    assert ccm.ll_nonce(counter, direction, IV) == bytes.fromhex(nonce)


@pytest.mark.parametrize(
    ("counter", "direction", "iv"),
    [
        pytest.param(-1, CENTRAL, IV, id="counter-negative"),
        pytest.param(1 << 39, CENTRAL, IV, id="counter-39-bits-plus-one"),
        pytest.param(0, 2, IV, id="direction-2"),
        pytest.param(0, CENTRAL, IV[:7], id="iv-7-octets"),
        pytest.param(0, CENTRAL, IV + b"\x00", id="iv-9-octets"),
    ],
)
def test_ll_nonce_rejects_bad_fields(counter, direction, iv):
    with pytest.raises(ValueError, match="must be"):
        ccm.ll_nonce(counter, direction, iv)


@pytest.mark.parametrize(
    ("header", "aad"),
    [
        pytest.param(0x02, "02", id="LL_DATA1-header"),
        pytest.param(0x03, "03", id="LL_START_ENC_RSP-header"),
        pytest.param(0xFF, "e3", id="NESN-SN-MD-masked-rest-kept"),
        pytest.param(0x04, "00", id="NESN-masked"),
        pytest.param(0x08, "00", id="SN-masked"),
        pytest.param(0x10, "00", id="MD-masked"),
        pytest.param(0x20, "20", id="CP-kept"),
    ],
)
def test_ll_aad_masks_nesn_sn_md(header, aad):
    """Vol 6 Part E Table 2.3: the header's first octet with NESN, SN and MD set to 0."""
    assert ccm.ll_aad(header) == bytes.fromhex(aad)


@pytest.mark.parametrize("header", [-1, 256])
def test_ll_aad_rejects_a_header_that_is_not_one_octet(header):
    with pytest.raises(ValueError, match="one octet"):
        ccm.ll_aad(header)


EAD_KEY = bytes.fromhex("57A9DA12D12E6E131E20612AD10A6A19")
EAD_IV = bytes.fromhex("46E77AB1EF007A9E")


@pytest.mark.parametrize(
    ("randomizer", "ad_data", "plaintext"),
    [
        pytest.param(
            0xDECA57E118,
            "18E157CADE 74E4DCAFDC51C7282810C2217F0E4CEF4343181F BA0069CC",
            "0f0953686f7274204d696e692d42757303190a8c",
            id="set-1",
        ),
        pytest.param(
            0x7A6E971C8D,
            "8D1C976E7A 35444076125788C238A58E8BD9CFF0DEFE251A8E 7275454C",
            "0f0953686f7274204d696e692d42757303190a8c",
            id="set-2-same-payload-new-randomizer",
        ),
    ],
)
def test_encrypted_data_matches_the_css_sample_data(randomizer, ad_data, plaintext):
    """CSS v11 Part A §2.3.1 and §2.3.2: Randomizer as packetCounter and directionBit, B1 octet 2 = 0xEA."""
    data = bytes.fromhex(ad_data)
    assert int.from_bytes(data[:5], "little") == randomizer
    nonce = ccm.ll_nonce(randomizer & (1 << 39) - 1, randomizer >> 39, EAD_IV)
    opened = ccm.decrypt(EAD_KEY, nonce, data[5:], b"\xea")
    assert opened == bytes.fromhex(plaintext)
    assert ccm.encrypt(EAD_KEY, nonce, opened, b"\xea") == data[5:]


def test_a_replayed_packet_fails_at_the_next_counter():
    aad = ccm.ll_aad(0x02)
    sealed = ccm.encrypt(SK, ccm.ll_nonce(0, CENTRAL, IV), b"payload", aad)
    with pytest.raises(ccm.InvalidTag):
        ccm.decrypt(SK, ccm.ll_nonce(1, CENTRAL, IV), sealed, aad)


def test_a_reflected_packet_fails_in_the_other_direction():
    aad = ccm.ll_aad(0x02)
    sealed = ccm.encrypt(SK, ccm.ll_nonce(0, CENTRAL, IV), b"payload", aad)
    with pytest.raises(ccm.InvalidTag):
        ccm.decrypt(SK, ccm.ll_nonce(0, PERIPHERAL, IV), sealed, aad)


@pytest.mark.parametrize("nonce_len", [7, 10, 13])
@pytest.mark.parametrize("tag_len", [4, 10, 16])
@pytest.mark.parametrize("aad", [b"", b"header", bytes(40)])
@pytest.mark.parametrize("length", [0, 1, 16, 33])
def test_ccm_matches_cryptography(nonce_len, tag_len, aad, length):
    key, nonce, plaintext = (
        bytes(range(16)),
        bytes(range(nonce_len)),
        bytes(range(length)),
    )
    sealed = AESCCM(key, tag_length=tag_len).encrypt(nonce, plaintext, aad)
    assert ccm.encrypt(key, nonce, plaintext, aad, tag_len) == sealed
    assert ccm.decrypt(key, nonce, sealed, aad, tag_len) == plaintext


@pytest.mark.parametrize(
    ("aad_len", "length"),
    [
        pytest.param(0xFEFF, 0, id="aad-0xFEFF"),
        pytest.param(0, 0xFFFF, id="payload-65535-with-L2"),
    ],
)
def test_ccm_accepts_the_largest_supported_sizes(aad_len, length):
    key, nonce, aad, plaintext = bytes(16), bytes(13), bytes(aad_len), bytes(length)
    expected = AESCCM(key, tag_length=4).encrypt(nonce, plaintext, aad)
    assert ccm.encrypt(key, nonce, plaintext, aad) == expected


def flip(data: bytes, i: int = 0) -> bytes:
    """data with the low bit of octet i flipped."""
    return data[:i] + bytes([data[i] ^ 1]) + data[i + 1 :]


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda k, n, s, a: (flip(k), n, s, a), id="wrong-key"),
        pytest.param(lambda k, n, s, a: (k, flip(n), s, a), id="wrong-nonce"),
        pytest.param(lambda k, n, s, a: (k, n, flip(s), a), id="flipped-ciphertext"),
        pytest.param(
            lambda k, n, s, a: (k, n, flip(s, len(s) - 1), a), id="flipped-mic"
        ),
        pytest.param(lambda k, n, s, a: (k, n, s[:-1], a), id="truncated"),
        pytest.param(lambda k, n, s, a: (k, n, s, b"\x03"), id="wrong-aad"),
        pytest.param(lambda k, n, s, a: (k, n, s, b""), id="missing-aad"),
    ],
)
def test_decrypt_rejects_anything_tampered(tamper):
    aad = b"\x02"
    sealed = ccm.encrypt(SK, NONCE, b"payload", aad)
    with pytest.raises(ccm.InvalidTag):
        ccm.decrypt(*tamper(SK, NONCE, sealed, aad))


@pytest.mark.parametrize(
    ("call", "message"),
    [
        pytest.param(
            lambda: ccm.encrypt(SK, bytes(6), b""), "nonce must be", id="nonce-6"
        ),
        pytest.param(
            lambda: ccm.encrypt(SK, bytes(14), b""), "nonce must be", id="nonce-14"
        ),
        pytest.param(
            lambda: ccm.encrypt(SK, NONCE, b"", tag_len=5), "tag_len must", id="tag-odd"
        ),
        pytest.param(
            lambda: ccm.encrypt(SK, NONCE, b"", tag_len=18), "tag_len must", id="tag-18"
        ),
        pytest.param(
            lambda: ccm.encrypt(SK, NONCE, b"", bytes(0xFF00)),
            "aad of 0xFF00",
            id="aad-too-long",
        ),
        pytest.param(
            lambda: ccm.encrypt(SK, bytes(13), bytes(65536)),
            "too long",
            id="payload-too-long-for-L2",
        ),
        pytest.param(
            lambda: ccm.decrypt(SK, NONCE, b"\x00"),
            "shorter than",
            id="sealed-shorter-than-tag",
        ),
        pytest.param(
            lambda: ccm.decrypt(bytes(15), NONCE, bytes(8)),
            "key must be 16",
            id="key-15",
        ),
    ],
)
def test_bad_parameters_are_rejected(call, message):
    with pytest.raises(ValueError, match=message):
        call()

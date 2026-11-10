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

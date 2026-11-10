"""AES-CCM (RFC 3610) written out for study, checked against cryptography's AESCCM; AES-128, as in BLE.

BLE uses a 13-octet nonce and a 4-octet MIC (Core v5.4 Vol 6 Part E §1), and so does Encrypted Advertising
Data (CSS v11 Part A §1.23). A (key, nonce) pair must never encrypt twice: CTR keystream reuse leaks the XOR
of the plaintexts.
"""

import hmac

from bt54.toolbox import e, xor

_BLOCK = 16


class InvalidTag(ValueError):
    """The tag does not verify: wrong key, nonce or aad, or tampered data."""


def _length_field_size(nonce: bytes, aad: bytes, tag_len: int, length: int) -> int:
    """Validate the parameters and return L, the octet size of the message-length field (15 - nonce)."""
    if not 7 <= len(nonce) <= 13:
        raise ValueError(f"nonce must be 7 to 13 octets, got {len(nonce)}")
    if tag_len not in (4, 6, 8, 10, 12, 14, 16):
        raise ValueError(f"tag_len must be an even number from 4 to 16, got {tag_len}")
    if len(aad) >= 0xFF00:
        raise ValueError("aad of 0xFF00 octets or more is not supported")
    size = 15 - len(nonce)
    if length >= 1 << (8 * size):
        raise ValueError(
            f"message of {length} octets is too long for a {len(nonce)}-octet nonce"
        )
    return size


def _pad(data: bytes) -> bytes:
    """Zero-pad data to a whole number of blocks."""
    return data + bytes(-len(data) % _BLOCK)


def _counter(nonce: bytes, i: int, size: int) -> bytes:
    """Counter block A_i = flags (L - 1) || nonce || i (RFC 3610 §2.3)."""
    return bytes([size - 1]) + nonce + i.to_bytes(size, "big")


def _mac(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, tag_len: int, size: int
) -> bytes:
    """CBC-MAC over B0 || encoded aad || plaintext (RFC 3610 §2.2), cut to tag_len octets."""
    flags = (0x40 if aad else 0) | ((tag_len - 2) // 2) << 3 | (size - 1)
    blocks = bytes([flags]) + nonce + len(plaintext).to_bytes(size, "big")
    if aad:
        blocks += _pad(len(aad).to_bytes(2, "big") + aad)
    blocks += _pad(plaintext)
    x = bytes(_BLOCK)
    for i in range(0, len(blocks), _BLOCK):
        x = e(key, xor(x, blocks[i : i + _BLOCK]))
    return x[:tag_len]


def _ctr(key: bytes, nonce: bytes, data: bytes, size: int) -> bytes:
    """XOR data with the keystream S_1, S_2, ... (RFC 3610 §2.3)."""
    count = -(-len(data) // _BLOCK)
    stream = b"".join(e(key, _counter(nonce, i, size)) for i in range(1, count + 1))
    return xor(data, stream[: len(data)])


def encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"", tag_len: int = 4
) -> bytes:
    """Return ciphertext || tag; tag_len 4 is the BLE MIC. Never reuse a nonce under the same key."""
    size = _length_field_size(nonce, aad, tag_len, len(plaintext))
    tag = _mac(key, nonce, plaintext, aad, tag_len, size)
    s0 = e(key, _counter(nonce, 0, size))
    return _ctr(key, nonce, plaintext, size) + xor(tag, s0[:tag_len])


def decrypt(
    key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"", tag_len: int = 4
) -> bytes:
    """Return the plaintext of ciphertext || tag; InvalidTag if it does not verify, ValueError on bad input."""
    if len(sealed) < tag_len:
        raise ValueError(
            f"sealed data of {len(sealed)} octets is shorter than the {tag_len}-octet tag"
        )
    size = _length_field_size(nonce, aad, tag_len, len(sealed) - tag_len)
    ciphertext, tag = sealed[:-tag_len], sealed[-tag_len:]
    plaintext = _ctr(key, nonce, ciphertext, size)
    s0 = e(key, _counter(nonce, 0, size))
    expected = xor(_mac(key, nonce, plaintext, aad, tag_len, size), s0[:tag_len])
    if not hmac.compare_digest(tag, expected):
        raise InvalidTag("CCM tag mismatch")
    return plaintext

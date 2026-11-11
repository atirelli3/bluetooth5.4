"""Encrypted Advertising Data (CSS v11 Part A §1.23): Randomizer (5) || encrypted Payload || MIC (4), on `bt54.ccm`."""

import secrets

from bt54 import ccm

_RANDOMIZER_SIZE = 5
_MIC_SIZE = 4
_AAD = b"\xea"


def _nonce(randomizer: bytes, iv: bytes) -> bytes:
    """CCM nonce (§1.23.3): packetCounter = Randomizer's low 39 bits, directionBit = its top bit; randomizer is LSO-first on air."""
    value = int.from_bytes(randomizer, "little")
    return ccm.ll_nonce(value & (2**39 - 1), value >> 39, iv)


def encrypt(
    key: bytes, iv: bytes, payload: bytes, randomizer: bytes | None = None
) -> bytes:
    """Return the Encrypted Data AD data: Randomizer || encrypted Payload || MIC. A new Randomizer is drawn if omitted.

    Never reuse a Randomizer under the same (key, iv), and never reuse iv once the session key changes (§1.23.4):
    either reuse leaks the CCM keystream. The 40-bit Randomizer also makes a birthday collision likely after about
    2^20 draws under one (key, iv); refresh iv (a new session key) well before that many advertisements.
    """
    if randomizer is None:
        randomizer = secrets.token_bytes(_RANDOMIZER_SIZE)
    if len(randomizer) != _RANDOMIZER_SIZE:
        raise ValueError(
            f"randomizer must be {_RANDOMIZER_SIZE} octets, got {len(randomizer)}"
        )
    return randomizer + ccm.encrypt(key, _nonce(randomizer, iv), payload, _AAD)


def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Return the Payload of Encrypted Data AD data; ccm.InvalidTag if it does not verify."""
    minimum = _RANDOMIZER_SIZE + _MIC_SIZE
    if len(data) < minimum:
        raise ValueError(f"data must be at least {minimum} octets, got {len(data)}")
    randomizer = data[:_RANDOMIZER_SIZE]
    return ccm.decrypt(key, _nonce(randomizer, iv), data[_RANDOMIZER_SIZE:], _AAD)

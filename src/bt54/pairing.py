"""LE Secure Connections pairing, Just Works and Numeric Comparison (Core v5.4 Vol 3 Part H §2.3.5.6); values MSB-first.

The central is the initiating device (A in f5/f6), the peripheral the responding one (B). Whether the users accept the
number is the caller's step, outside this module. `mask_key_bredr` is the BR/EDR counterpart of `mask_key`, kept here
beside it because the two rules are opposite.
"""

import hmac
import secrets
from dataclasses import dataclass
from enum import IntEnum

from bt54.device import AuthReq, BTDevice
from bt54.toolbox import f4, f5, f6, g2

_MIN_KEY_SIZE = 7
_NO_OOB = 0
_Z = bytes(1)
_R = bytes(16)


class Reason(IntEnum):
    """Pairing Failed reason codes (Vol 3 Part H §3.5.5 Table 3.7)."""

    CONFIRM_VALUE_FAILED = 0x04
    ENCRYPTION_KEY_SIZE = 0x06
    DHKEY_CHECK_FAILED = 0x0B
    NUMERIC_COMPARISON_FAILED = 0x0C


class PairingFailed(Exception):
    """The pairing is aborted with a Pairing Failed command carrying `reason`."""

    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.name)
        self.reason = reason


@dataclass(frozen=True)
class Exchange:
    """Stage 1 of one pairing: the agreed key size, each side's 32-octet DHKey, Na and Nb (16), the 6-digit number."""

    central: BTDevice
    peripheral: BTDevice
    key_size: int
    dhkey_c: bytes
    dhkey_p: bytes
    na: bytes
    nb: bytes
    number: int


def _require_mask_args(key: bytes, size: int) -> None:
    """Raise ValueError unless key is 16 octets and size is 1 to 16."""
    if len(key) != 16:
        raise ValueError(f"key must be 16 octets, got {len(key)}")
    if not 1 <= size <= 16:
        raise ValueError(f"size must be 1 to 16, got {size}")


def mask_key(key: bytes, size: int) -> bytes:
    """LE encryption key size reduction (Vol 3 Part H §2.3.4): the 16 - size most significant octets set to 0."""
    _require_mask_args(key, size)
    return bytes(16 - size) + key[16 - size :]


def mask_key_bredr(key: bytes, size: int) -> bytes:
    """BR/EDR AES-CCM key size reduction (Vol 2 Part H §9.4): the 16 - size least significant octets set to 0."""
    _require_mask_args(key, size)
    return key[:size] + bytes(16 - size)


def check_commit(commit: bytes, pk_a: bytes, pk_b: bytes, nb: bytes) -> None:
    """Initiator's check of Cb = f4(PKbx, PKax, Nb, 0) (§2.3.5.6.2); pk_a, pk_b 32 octets, nb 16; CONFIRM_VALUE_FAILED."""
    if not hmac.compare_digest(commit, f4(pk_b, pk_a, nb, _Z)):
        raise PairingFailed(Reason.CONFIRM_VALUE_FAILED)


def exchange(central: BTDevice, peripheral: BTDevice) -> Exchange:
    """Key size (§2.3.4: the shorter maximum, at least 7) and stage 1 (§2.3.5.6.2): DHKeys, Cb, Na, Nb, g2 mod 10^6.

    Both devices must set SC (§3.5.1; legacy pairing is not simulated). Cb is checked against the nonce this call
    drew, so it cannot fail here: a scenario that tampers with Nb or Cb calls `check_commit` with its own values.
    """
    if not central.auth_req & peripheral.auth_req & AuthReq.SC:
        raise ValueError(
            "both devices must set the SC flag: legacy pairing is not simulated"
        )
    key_size = min(central.max_key_size, peripheral.max_key_size)
    if key_size < _MIN_KEY_SIZE:
        raise PairingFailed(Reason.ENCRYPTION_KEY_SIZE)
    dhkey_c = central.compute_dh_key(peripheral.pK)
    dhkey_p = peripheral.compute_dh_key(central.pK)
    pk_a, pk_b = (d.pK_x.to_bytes(32) for d in (central, peripheral))
    na, nb = secrets.token_bytes(16), secrets.token_bytes(16)
    check_commit(f4(pk_b, pk_a, nb, _Z), pk_a, pk_b, nb)
    number = g2(pk_a, pk_b, na, nb) % 10**6
    return Exchange(central, peripheral, key_size, dhkey_c, dhkey_p, na, nb, number)


def _io_cap(device: BTDevice) -> bytes:
    """IOcap of f6 (§2.3.5.6.5): AuthReq || OOB flag || IO capability, 3 octets."""
    return bytes([device.auth_req, _NO_OOB, device.IOCap])


def authenticate(x: Exchange) -> bytes:
    """Stage 2 (§2.3.5.6.5): both sides run f5, the responder checks Ea, then the initiator checks Eb; returns the LTK.

    DHKEY_CHECK_FAILED when the two sides' DHKeys differ. The 16-octet LTK is masked to the agreed key size.
    """
    a, b = x.central.pairing_address, x.peripheral.pairing_address
    io_a, io_b = _io_cap(x.central), _io_cap(x.peripheral)
    mac_c, ltk = f5(x.dhkey_c, x.na, x.nb, a, b)
    mac_p, _ = f5(x.dhkey_p, x.na, x.nb, a, b)
    ea = f6(mac_c, x.na, x.nb, _R, io_a, a, b)
    if not hmac.compare_digest(ea, f6(mac_p, x.na, x.nb, _R, io_a, a, b)):
        raise PairingFailed(Reason.DHKEY_CHECK_FAILED)
    eb = f6(mac_p, x.nb, x.na, _R, io_b, b, a)
    if not hmac.compare_digest(eb, f6(mac_c, x.nb, x.na, _R, io_b, b, a)):
        raise PairingFailed(Reason.DHKEY_CHECK_FAILED)
    return mask_key(ltk, x.key_size)

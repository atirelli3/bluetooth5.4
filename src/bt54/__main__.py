"""Scenario CLI, `python -m bt54 <scenario>|all`: each scenario runs on simulated devices and prints expected vs actual.

Exit code 0 when every scenario reached its expected outcome, 1 otherwise. Simulation only: no radio, no real devices.
"""

import argparse
import secrets
import sys
import time
from collections.abc import Callable
from functools import partial

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from bt54 import ccm
from bt54.device import AuthReq, BTDevice, IOCap
from bt54.pairing import (
    PairingFailed,
    Reason,
    authenticate,
    exchange,
    mask_key_bredr,
)
from bt54.toolbox import e

MESSAGE = b"secret LE data"
_CENTRAL = 1
_HEADER = 0x02
_JUST_WORKS = partial(
    BTDevice, iocap=IOCap.NO_INPUT_NO_OUTPUT, auth_req=AuthReq.BONDING | AuthReq.SC
)
_NUMERIC = partial(
    BTDevice,
    iocap=IOCap.DISPLAY_YES_NO,
    auth_req=AuthReq.BONDING | AuthReq.MITM | AuthReq.SC,
)
_SECONDS_PER_YEAR = 365 * 24 * 3600
_SECONDS_PER_DAY = 24 * 3600
_ASSUMED_RATE_EXPONENT = 10
_FLOOR_TRIALS_EXPONENT = 56
_NATIVE_SAMPLE = 20_000
_PAIRED = "paired; packet decrypts"
_RELAYED = "paired with both victims; Eve reads and relays the packet"


def _failed(reason: Reason) -> str:
    """The outcome string of a Pairing Failed with this reason."""
    return f"pairing failed: {reason.name}"


def _session(ltk: bytes) -> tuple[bytes, bytes]:
    """SK = e(LTK, SKD) (Vol 6 Part B §5.1.3.1) for a random 16-octet SKD, and a random 8-octet IV: (SK, IV)."""
    return e(ltk, secrets.token_bytes(16)), secrets.token_bytes(8)


def _seal(link: tuple[bytes, bytes], data: bytes) -> bytes:
    """The first packet of a link (counter 0, Central to Peripheral), encrypted with its SK and IV."""
    sk, iv = link
    return ccm.encrypt(sk, ccm.ll_nonce(0, _CENTRAL, iv), data, ccm.ll_aad(_HEADER))


def _open(link: tuple[bytes, bytes], sealed: bytes) -> bytes:
    """Decrypt the first packet of a link; ccm.InvalidTag if it does not verify."""
    sk, iv = link
    return ccm.decrypt(sk, ccm.ll_nonce(0, _CENTRAL, iv), sealed, ccm.ll_aad(_HEADER))


def _opens(link: tuple[bytes, bytes], sealed: bytes) -> bool:
    """Whether the link's key verifies this packet."""
    try:
        _open(link, sealed)
    except ccm.InvalidTag:
        return False
    return True


def _pair_and_talk(new_device: Callable[[], BTDevice]) -> str:
    """Two devices pair, then Alice sends one encrypted packet to Bob."""
    alice, bob = new_device(), new_device()
    x = exchange(alice, bob)
    if alice.auth_req & AuthReq.MITM:
        print(f"  number shown to both users: {x.number:06d}")
    link = _session(authenticate(x))
    _open(link, _seal(link, MESSAGE))
    return _PAIRED


def _mitm(compare_numbers: bool, new_device: Callable[[], BTDevice]) -> str:
    """Eve pairs with Alice (as peripheral) and with Bob (as central), reads Alice's packet and relays it to Bob.

    With compare_numbers the users check the two 6-digit numbers. They collide with p = 10^-6, which would let Eve
    through, so the scenario redraws that case to keep its outcome deterministic.
    """
    alice, eve, bob = new_device(), new_device(), new_device()
    to_alice, to_bob = exchange(alice, eve), exchange(eve, bob)
    while compare_numbers and to_alice.number == to_bob.number:
        to_bob = exchange(eve, bob)
    if alice.auth_req & AuthReq.MITM:
        print(f"  Alice sees {to_alice.number:06d}, Bob sees {to_bob.number:06d}")
    if compare_numbers:
        raise PairingFailed(Reason.NUMERIC_COMPARISON_FAILED)
    alice_link = _session(authenticate(to_alice))
    bob_link = _session(authenticate(to_bob))
    sent = _seal(alice_link, MESSAGE)
    if _opens(bob_link, sent):
        return "no MitM: both links share a key"
    stolen = _open(alice_link, sent)
    print(f"  Eve read: {stolen.decode()}")
    _open(bob_link, _seal(bob_link, stolen))
    return _RELAYED


def _recover_key(
    sealed: bytes, nonce: bytes, aad: bytes, size: int, *, bredr: bool = False
) -> tuple[bytes | None, int]:
    """Brute force over the keys of `size` octets: (key or None, trials); only InvalidTag means 'wrong key'.

    LE keys have their 16 - size most significant octets zeroed, BR/EDR keys their least significant ones.
    """
    for trials, candidate in enumerate(range(256**size), start=1):
        key = (
            candidate.to_bytes(size) + bytes(16 - size)
            if bredr
            else candidate.to_bytes(16)
        )
        try:
            ccm.decrypt(key, nonce, sealed, aad)
        except ccm.InvalidTag:
            continue
        return key, trials
    return None, 256**size


def _native_rate(sealed: bytes, nonce: bytes, aad: bytes) -> float:
    """Trials per second of cryptography's native AESCCM (4-octet tag) over wrong keys, called from a Python loop."""
    started = time.perf_counter()
    for candidate in range(_NATIVE_SAMPLE):
        try:
            AESCCM(candidate.to_bytes(16), tag_length=4).decrypt(nonce, sealed, aad)
        except InvalidTag:
            continue
    return _NATIVE_SAMPLE / (time.perf_counter() - started)


def _duration(rate: float) -> str:
    """How long 2^56 trials take at `rate` trials per second: in years from one year up, else in days."""
    seconds = 2**_FLOOR_TRIALS_EXPONENT / rate
    if seconds >= _SECONDS_PER_YEAR:
        return f"{seconds / _SECONDS_PER_YEAR:,.0f} years"
    return f"{seconds / _SECONDS_PER_DAY:,.0f} days"


def knob_bredr() -> str:
    """BR/EDR KNOB (CVE-2019-9506): entropy negotiated down to 1 octet, so 256 trials recover the key.

    Models the AES-CCM key reduction of Vol 2 Part H §9.4 (E0 reduces its key differently, not modelled). The packet
    framing is simplified: the LE nonce size and AAD are reused.
    """
    key = mask_key_bredr(secrets.token_bytes(16), 1)
    nonce = secrets.token_bytes(13)
    aad = ccm.ll_aad(_HEADER)
    sealed = ccm.encrypt(key, nonce, MESSAGE, aad)
    found, trials = _recover_key(sealed, nonce, aad, 1, bredr=True)
    print(f"  session key (1 octet): {key.hex()}, found after {trials} trials")
    return "key recovered" if found == key else "key not recovered"


def knob_le() -> str:
    """LE floor of 7 octets (Vol 3 Part H §2.3.4): a 1-octet offer is refused; 2^56 trials, measured and assumed."""
    try:
        exchange(_JUST_WORKS(max_key_size=1), _JUST_WORKS())
    except PairingFailed as failed:
        refusal = _failed(failed.reason)
    else:
        refusal = "pairing accepted a 1-octet key"
    key, nonce = bytes(range(1, 17)), secrets.token_bytes(13)
    aad = ccm.ll_aad(_HEADER)
    sealed = ccm.encrypt(key, nonce, MESSAGE, aad)
    started = time.perf_counter()
    _, trials = _recover_key(sealed, nonce, aad, 1)
    hand_rolled = trials / (time.perf_counter() - started)
    hardware = 10**_ASSUMED_RATE_EXPONENT
    print("  2^56 trials (the 7-octet floor):")
    for label, rate in (
        ("hand-rolled CCM, one core", hand_rolled),
        ("AESCCM in a Python loop, one core", _native_rate(sealed, nonce, aad)),
        ("assumed attacker hardware", hardware),
    ):
        print(f"    {label:<36}{rate:>14,.0f} trials/s  {_duration(rate)}")
    return f"{refusal}; 2^56 trials take {_duration(hardware)} at an assumed 10^{_ASSUMED_RATE_EXPONENT} trials/s"


SCENARIOS: dict[str, tuple[str, Callable[[], str]]] = {
    "just-works": (_PAIRED, lambda: _pair_and_talk(_JUST_WORKS)),
    "just-works-mitm": (_RELAYED, lambda: _mitm(False, _JUST_WORKS)),
    "numeric-comparison": (_PAIRED, lambda: _pair_and_talk(_NUMERIC)),
    "numeric-comparison-mitm": (
        _failed(Reason.NUMERIC_COMPARISON_FAILED),
        lambda: _mitm(True, _NUMERIC),
    ),
    "numeric-comparison-mitm-blind": (_RELAYED, lambda: _mitm(False, _NUMERIC)),
    "knob-bredr": ("key recovered", knob_bredr),
    "knob-le": (
        "pairing failed: ENCRYPTION_KEY_SIZE; 2^56 trials take 83 days at an assumed 10^10 trials/s",
        knob_le,
    ),
}


def main(argv: list[str] | None = None) -> int:
    """Run one scenario or all of them; print name, expected, actual and PASS/FAIL; 0 if all pass, else 1."""
    parser = argparse.ArgumentParser(prog="python -m bt54", description=__doc__)
    parser.add_argument("scenario", choices=[*SCENARIOS, "all"])
    chosen = parser.parse_args(argv).scenario
    failures = 0
    for name in SCENARIOS if chosen == "all" else [chosen]:
        expected, run = SCENARIOS[name]
        print(name)
        try:
            actual = run()
        except PairingFailed as failed:
            actual = _failed(failed.reason)
        except ccm.InvalidTag:
            actual = "a packet failed to verify"
        passed = actual == expected
        failures += not passed
        print(
            f"  expected: {expected}\n  actual:   {actual}\n  {'PASS' if passed else 'FAIL'}"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

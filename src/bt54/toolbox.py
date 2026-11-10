"""Security Manager cryptographic toolbox (Core v5.4 Vol 3 Part H §2.2); every value is an MSB-first octet string."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

F5_SALT = bytes.fromhex("6C888391AAF5A53860370BDB5A6083BE")


def _require(**fields: tuple[bytes, int]) -> None:
    """Raise ValueError naming the first field whose length is not its expected octet count."""
    for name, (value, octets) in fields.items():
        if len(value) != octets:
            raise ValueError(f"{name} must be {octets} octets, got {len(value)}")


def xor(a: bytes, b: bytes) -> bytes:
    """Octet-wise XOR of two equal-length strings."""
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def e(key: bytes, plaintext: bytes) -> bytes:
    """Security function e (§2.2.1): AES-128 of one 16-octet block under a 16-octet key."""
    _require(key=(key, 16), plaintext=(plaintext, 16))
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC (§2.2.5, RFC 4493): the 16-octet MAC of message under a 16-octet key."""
    _require(key=(key, 16))
    mac = CMAC(algorithms.AES(key))
    mac.update(message)
    return mac.finalize()


def c1(
    k: bytes,
    r: bytes,
    preq: bytes,
    pres: bytes,
    iat: int,
    rat: int,
    ia: bytes,
    ra: bytes,
) -> bytes:
    """LE legacy confirm value (§2.2.3): k, r 16 octets; preq, pres 7; ia, ra 6; iat, rat 0 public / 1 random."""
    _require(
        k=(k, 16), r=(r, 16), preq=(preq, 7), pres=(pres, 7), ia=(ia, 6), ra=(ra, 6)
    )
    if iat not in (0, 1) or rat not in (0, 1):
        raise ValueError(f"iat and rat must be 0 or 1, got {iat} and {rat}")
    p1 = pres + preq + bytes([rat, iat])
    p2 = bytes(4) + ia + ra
    return e(k, xor(e(k, xor(r, p1)), p2))


def s1(k: bytes, r1: bytes, r2: bytes) -> bytes:
    """LE legacy STK (§2.2.4): e(k, r1' || r2'), r' being the low 64 bits of each 16-octet r."""
    _require(k=(k, 16), r1=(r1, 16), r2=(r2, 16))
    return e(k, r1[8:] + r2[8:])


def f4(U: bytes, V: bytes, X: bytes, Z: bytes) -> bytes:
    """LE SC confirm value (§2.2.6): AES-CMAC_X(U || V || Z); U, V 32 octets, X 16, Z 1."""
    _require(U=(U, 32), V=(V, 32), X=(X, 16), Z=(Z, 1))
    return aes_cmac(X, U + V + Z)


def f5(W: bytes, N1: bytes, N2: bytes, A1: bytes, A2: bytes) -> tuple[bytes, bytes]:
    """LE SC key generation (§2.2.7): (MacKey, LTK) from DHKey W (32 octets), N1, N2 (16), A1, A2 (7)."""
    _require(W=(W, 32), N1=(N1, 16), N2=(N2, 16), A1=(A1, 7), A2=(A2, 7))
    t = aes_cmac(F5_SALT, W)
    body = b"btle" + N1 + N2 + A1 + A2 + b"\x01\x00"
    return aes_cmac(t, b"\x00" + body), aes_cmac(t, b"\x01" + body)


def f6(
    W: bytes, N1: bytes, N2: bytes, R: bytes, IOcap: bytes, A1: bytes, A2: bytes
) -> bytes:
    """LE SC check value (§2.2.8): AES-CMAC_W(N1 || N2 || R || IOcap || A1 || A2); IOcap 3 octets, A1, A2 7, rest 16."""
    _require(
        W=(W, 16),
        N1=(N1, 16),
        N2=(N2, 16),
        R=(R, 16),
        IOcap=(IOcap, 3),
        A1=(A1, 7),
        A2=(A2, 7),
    )
    return aes_cmac(W, N1 + N2 + R + IOcap + A1 + A2)


def g2(U: bytes, V: bytes, X: bytes, Y: bytes) -> int:
    """LE SC numeric comparison (§2.2.9): AES-CMAC_X(U || V || Y) mod 2^32; users see it mod 10^6, 6 digits."""
    _require(U=(U, 32), V=(V, 32), X=(X, 16), Y=(Y, 16))
    return int.from_bytes(aes_cmac(X, U + V + Y)[-4:])


def h6(W: bytes, keyID: str) -> bytes:
    """Link key conversion (§2.2.10): AES-CMAC_W(keyID); W 16 octets, keyID 4 ASCII characters."""
    key_id = keyID.encode("ascii")
    _require(W=(W, 16), keyID=(key_id, 4))
    return aes_cmac(W, key_id)


def h7(SALT: bytes, W: bytes) -> bytes:
    """Link key conversion (§2.2.11): AES-CMAC_SALT(W); SALT and W 16 octets."""
    _require(SALT=(SALT, 16), W=(W, 16))
    return aes_cmac(SALT, W)

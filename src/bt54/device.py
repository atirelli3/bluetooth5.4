"""Simulated Bluetooth LE device: P-256 key pair, ECDH with peer-key checks, IO capability, identity address."""

import secrets

from cryptography.hazmat.primitives.asymmetric import ec

_RANDOM_PART = (1 << 46) - 1


class InvalidPublicKey(ValueError):
    """A peer public key the pairing must refuse: off the P-256 curve, or with our own X coordinate."""


def random_static_address() -> bytes:
    """Random static address (Vol 6 Part B §1.3.2.1): 6 octets, MSBs 0b11, random part neither all 0s nor all 1s."""
    while True:
        draw = secrets.token_bytes(6)
        address = bytes([draw[0] | 0xC0]) + draw[1:]
        if (int.from_bytes(address) & _RANDOM_PART) not in (0, _RANDOM_PART):
            return address


def load_public_key(x: bytes, y: bytes) -> ec.EllipticCurvePublicKey:
    """P-256 key from a Pairing Public Key's 32-octet X and Y (MSB-first); InvalidPublicKey when off the curve."""
    if len(x) != 32 or len(y) != 32:
        raise ValueError(f"x and y must be 32 octets, got {len(x)} and {len(y)}")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x), int.from_bytes(y), ec.SECP256R1()
    )
    try:
        return numbers.public_key()
    except ValueError as error:
        raise InvalidPublicKey(
            f"point is not on P-256 (CVE-2018-5383): {error}"
        ) from error


class BTDevice:
    """A pairing party: P-256 key pair (pK, pK_x), IOCap (4 = KeyboardDisplay), address, dhkey once computed."""

    def __init__(
        self, iocap: int = 4, address: bytes | None = None, address_type: int = 1
    ) -> None:
        if address is None:
            if address_type != 1:
                raise ValueError(
                    "a generated address is random static: address_type must be 1"
                )
            address = random_static_address()
        if len(address) != 6:
            raise ValueError(f"address must be 6 octets, got {len(address)}")
        if address_type not in (0, 1):
            raise ValueError(
                f"address_type must be 0 or 1 (public / random), got {address_type}"
            )
        self._sk = ec.generate_private_key(ec.SECP256R1())
        self.pK = self._sk.public_key()
        self.pK_x = self.pK.public_numbers().x
        self.IOCap = iocap
        self.address = address
        self.address_type = address_type
        self.dhkey: bytes | None = None

    @property
    def pairing_address(self) -> bytes:
        """A1/A2 of f5 and f6 (Vol 3 Part H §2.2.7): the address type octet || the 6-octet address."""
        return bytes([self.address_type]) + self.address

    def compute_dh_key(self, peer: ec.EllipticCurvePublicKey) -> bytes:
        """Set and return dhkey, the 32-octet ECDH secret; InvalidPublicKey (dhkey None) if peer has our X (§2.3.5.6.1)."""
        self.dhkey = None
        if peer.public_numbers().x == self.pK_x:
            raise InvalidPublicKey("peer public key has the same X coordinate as ours")
        self.dhkey = self._sk.exchange(ec.ECDH(), peer)
        return self.dhkey

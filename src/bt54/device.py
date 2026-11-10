"""Simulated Bluetooth device: P-256 key pair, ECDH, IO capability and address."""

import random

from cryptography.hazmat.primitives.asymmetric import ec


class BTDevice:
    """A pairing party: P-256 key pair (pK_x, pK_y as ints), IOCap, and dhkey / nonce set while pairing."""

    def __init__(self, iocap=4, bt_address=None):
        self.sK = ec.generate_private_key(ec.SECP256R1())
        self.pK = self.sK.public_key()
        coordinate = self.pK.public_numbers()
        self.pK_x = coordinate.x
        self.pK_y = coordinate.y
        self.IOCap = iocap
        self.dhkey = None
        self.nonce = None
        if bt_address is None:
            self.address = self.generate_random_bt_address()
        else:
            self.address = bt_address

    def generate_random_bt_address(self):
        """Random address string: an odd first octet, then 6 random octets ("XX:XX:...", 7 octets)."""
        bt_address_bytes = [random.randint(0, 255) for _ in range(6)]
        msb = random.randint(0, 127) * 2 + 1
        bt_address_bytes.insert(0, msb)
        return ":".join(f"{byte:02X}" for byte in bt_address_bytes)

    def computeDHKey(self, remote_public_key):
        """Set dhkey to the 32-octet ECDH shared secret with remote_public_key."""
        self.dhkey = self.sK.exchange(ec.ECDH(), remote_public_key)

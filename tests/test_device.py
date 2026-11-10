"""BTDevice: P-256 key pair and ECDH."""

from bt54.device import BTDevice


def test_two_devices_agree_on_a_32_octet_dhkey():
    alice, bob = BTDevice(), BTDevice()
    alice.computeDHKey(bob.pK)
    bob.computeDHKey(alice.pK)
    assert alice.dhkey == bob.dhkey
    assert len(alice.dhkey) == 32

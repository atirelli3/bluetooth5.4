# Pairing — memory

LE Legacy (Just Works, Passkey, OOB) and LE Secure Connections (Just Works, Numeric Comparison, Passkey, OOB):
feature exchange, key generation, LTK, key derivation.

## A Just Works MitM is two pairings, not one tampered pairing
- **Rule:** simulate a MitM on Just Works as two independent, successful LE SC pairings (Alice↔Eve and Eve↔Bob),
  with Eve holding both LTKs. Never model it as a swapped nonce inside one pairing.
- **Why:** the 2024 demo swapped Bob's nonce inside a single pairing. The f6 check then fails because the two LTKs
  differ, and the demo prints "MitM detected" (run 2026-11-10). The real weakness is that Just Works shows the user
  no value to confirm, so nothing binds the two ECDH exchanges together.
- **Where:** `src/demo.py` `just_work()`; the future `bt54` MitM scenario.

## A1/A2 are the address type octet, then the 6-octet address
- **Rule:** f5 and f6 take `pairing_address`, which is the type octet (0 public, 1 random) followed by the 6-octet
  address. The default random static address comes from `secrets`: bits 47:46 = 0b11, and the random part is
  neither all 0s nor all 1s.
- **Why:**
  - spec: Vol 3 Part H §2.2.7, Appendix D.3 (`00 561237 37bfce`), Vol 6 Part B §1.3.2.1;
  - the 2024 code used `random` and a random odd first octet (Audit #1 L1).
- **Where:** `src/bt54/device.py` `random_static_address`, `BTDevice.pairing_address`.

## Refuse a peer key that has our X or is off the curve
- **Rule:** `compute_dh_key` raises `InvalidPublicKey` when the peer has our X coordinate (the sim has no debug key).
  A received X/Y pair goes through `load_public_key`, which raises the same error for points off P-256.
- **Why:**
  - the same-X rule is Vol 3 Part H §2.3.5.6.1 ("each device should fail the pairing process");
  - off-curve points are CVE-2018-5383 (invalid curve). `cryptography` already refuses them; the named error lets
    a scenario show the check.
- **Where:** `src/bt54/device.py`.

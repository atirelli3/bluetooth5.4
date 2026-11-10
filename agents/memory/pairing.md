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

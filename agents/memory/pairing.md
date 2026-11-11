# Pairing — memory

LE Legacy (Just Works, Passkey, OOB) and LE Secure Connections (Just Works, Numeric Comparison, Passkey, OOB):
feature exchange, key generation, LTK, key derivation.

## A Just Works MitM is two pairings, not one tampered pairing
- **Rule:** simulate a MitM on Just Works as two independent, successful LE SC pairings (Alice↔Eve and Eve↔Bob),
  with Eve holding both LTKs. Never model it as a swapped nonce inside one pairing.
- **Why:** the 2024 demo swapped Bob's nonce inside a single pairing. The f6 check then fails because the two LTKs
  differ, and the demo prints "MitM detected" (run 2026-11-10). The real weakness is that Just Works shows the user
  no value to confirm, so nothing binds the two ECDH exchanges together.
- **Where:** `src/bt54/__main__.py` `_mitm` (scenarios `just-works-mitm`, `numeric-comparison-mitm-blind`).

## Stage 1 runs the Cb check in Just Works too; only the user step is missing
- **Rule:** `exchange()` checks Cb = f4(PKbx, PKax, Nb, 0) for both methods, and the 6-digit number is shown only with
  the MITM flag (Numeric Comparison). A Numeric Comparison MitM is two `exchange()` calls whose numbers the users
  compare; the library never decides that, the scenario raises `NUMERIC_COMPARISON_FAILED`.
- **Why:**
  - Figure 2.3 (read 2026-11-11 from the spec's PNG, `Core-54/out/en/image/1653f7aca34911.png`) puts step 6a, "Check
    if Cb = f4(PKb, PKa, Nb, 0); if the check fails, abort", in the Just Works flow. Steps 7a and 7b are the Va/Vb
    computations: the sentence in §2.3.5.6.2 ("the commitment checks (steps 7a and 7b) are not performed") means the
    number is not shown, not that Cb is skipped;
  - Audit #1 P1 read that sentence as "Just Works skips the commit check", which is wrong; Linux's `smp.c` agrees
    with the figure;
  - the outcome of every scenario is the same either way: Eve's two pairings are honest, so the check passes.
- **Where:** `src/bt54/pairing.py` `exchange`, `check_commit`.

## The simulated Cb, Ea and Eb checks fail only through a DHKey mismatch (known limit)
- **Rule:** both sides of `exchange`/`authenticate` read the same device objects, so IOcap, AuthReq, address or
  nonce tampering cannot be modelled yet, and the Cb check cannot fail unless a scenario calls `check_commit` with
  its own value. Tests pin the arguments with spies instead (`test_authenticate_feeds_f6_the_spec_arguments`).
  The association model is not chosen from IOCap either; both devices must set SC, or `exchange` raises.
- **Why:** per-side views are needed for Method Confusion and an IOcap downgrade (step 6); until then they are
  YAGNI (reviews of 2026-11-11: security-reviewer, silent-failure-hunter). User decision: build them in step 6,
  with Method Confusion (`decisions.md`).
- **Where:** `src/bt54/pairing.py`.

## The negotiated key size masks the LTK, and below 7 octets the pairing fails
- **Rule:** key size = the shorter of the two `max_key_size`; under 7 → `PairingFailed(ENCRYPTION_KEY_SIZE)`; the
  LTK from f5 is masked to that size (`mask_key`, the most significant octets become 0).
- **Why:** Vol 3 Part H §2.3.4 (range 7–16, shorter maximum wins, masking example) and §2.4.4.2 (the LE SC LTK is
  shortened too). Nothing in f6 or f5 covers the key size: this is the gap the key-size downgrade (Audit #1 R1) uses.
- **Where:** `src/bt54/pairing.py` `exchange`, `authenticate`, `mask_key`.

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

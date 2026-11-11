# Attacks — memory

KNOB, the Just Works MitM, and the roadmap attacks (Legacy TK brute force, Method Confusion, BLURtooth/CTKD,
EAD/CCM misuse): threat models, preconditions, how each scenario is simulated, its expected outcome.

Each attack adds its lessons here when its scenario is built; write-ups go to `docs/attacks/` (step 5).

## A relaying MitM must decrypt and re-encrypt: the two links have different session keys
- **Rule:** Eve is one `BTDevice` with two `exchange()` runs (peripheral toward Alice, central toward Bob). She opens
  Alice's packet with SK_AE and seals it again with SK_EB; forwarding the ciphertext fails the MIC.
- **Why:** each pairing gives its own LTK, so its own SK = e(LTK, SKD). The success test is `stolen == received ==
  MESSAGE`, not "pairing finished" (Audit #1 P1, P7).
- **Where:** `src/bt54/__main__.py` `_mitm`.

## Numeric Comparison catches a MitM only when the users compare the numbers
- **Rule:** with two exchanges the numbers differ with p = 1 - 10^-6. `numeric-comparison-mitm` (users compare) ends
  in `NUMERIC_COMPARISON_FAILED`; `numeric-comparison-mitm-blind` (users accept) ends in a relayed packet. The
  scenario redraws the rare collision to stay deterministic: in the real attack a collision lets Eve through.
- **Why:** nothing but the human step binds the two ECDH runs (Audit #1 P2).
- **Where:** `src/bt54/__main__.py` `_mitm(compare_numbers=...)`.

## KNOB is BR/EDR; LE has a floor of 7 octets, so `knob-le` shows the refusal and an extrapolation
- **Rule:** `knob-bredr` masks the key to 1 octet (the MSOs become 0) and recovers it in at most 256 trials
  (CVE-2019-9506). `knob-le` shows a 1-octet offer refused (`ENCRYPTION_KEY_SIZE`) and prices the 2^56 trials of
  the 7-octet floor at an assumed 10^10 trials/s: 83 days (the verdict). It prints a three-row table: the hand-rolled
  CCM (about 4·10^4 trials/s, 56,000 years), `cryptography`'s AESCCM in a Python loop (about 6.5·10^5 trials/s,
  3,400 years) and the assumed hardware. The first two rows are measured on the running machine and only printed.
- **Why (verdict wording):** 7 octets is the spec floor, not a strong key; "infeasible" holds only at the speed of
  the didactic CCM (review of 2026-11-11). `knob-bredr` reuses the LE nonce size and AAD (framing simplified).
- **Why:** LE negotiates 7–16 octets (§2.3.4, Audit #1 P3, P4); the 2024 demo kept the leading octets and used an
  illegal 1-octet LE key. The LE downgrade to 7 octets (R1) is a step-6 scenario.
- **Where:** `src/bt54/__main__.py` `knob_bredr`, `knob_le`, `_recover_key`.

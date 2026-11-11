# EAD and CCM — memory

AES-CCM in the LE link layer and in Encrypted Advertising Data (Core 5.4), the key material, PAwR.

## Encrypted Data AD type layout
- **Rule:** the Encrypted Data payload is Randomizer (5 octets) ‖ encrypted Payload (a sequence of AD structures) ‖
  MIC (4 octets). It is encrypted with the CCM of Vol 6 Part E §1, with these changes:
  - packetCounter = Randomizer, and directionBit = the MSB of the Randomizer;
  - IV = the pre-shared IV;
  - octet 2 of B1 = 0xEA.

  The CCM nonce is therefore 13 octets (Randomizer 5 ‖ IV 8). A new Randomizer is due every time the payload or the
  random address changes, and a new IV every time the session key changes.
- **Why:** CSS v11 Part A §1.23 (read 2026-11-10, re-confirmed 2026-11-11 against §1.23.3/§1.23.4). The sample sets of
  §2.3.1 and §2.3.2 pass through `bt54.ead`: nonce = `ccm.ll_nonce(R & (2**39 - 1), R >> 39, IV)` with R the
  Randomizer as an integer (the AD data carries it least significant octet first), AAD = `b"\xea"`, key and IV
  MSB-first as printed. The 40-bit Randomizer makes a birthday collision likely after about 2^20 draws under one
  (key, IV): `ead.encrypt`'s docstring carries the reuse warning, caller's job to refresh iv/randomizer.
- **Where:** `src/bt54/ead.py` (`encrypt`, `decrypt`, `_nonce`); `tests/test_ead.py`; the `ead` CLI scenario.

## Brute-force loops catch InvalidTag, never ValueError
- **Rule:** `bt54.ccm.decrypt` raises `ccm.InvalidTag` (a `ValueError` subclass) only when the tag fails to verify,
  and a plain `ValueError` for bad parameters. Any key-search loop catches `ccm.InvalidTag` only.
- **Why:** with `except ValueError`, a wrong-length key or nonce fails on every candidate, the loop finds nothing,
  and the KNOB demo prints "key not found", a fake successful defence (silent-failure review 2026-11-10).
  Mutation check: with `hmac.compare_digest` forced to True, all 7 tamper tests fail.
- **Where:** `src/bt54/ccm.py` `decrypt`; `src/bt54/__main__.py` `_recover_key`, tested by
  `test_the_brute_force_does_not_hide_a_bad_parameter`.

## The LE link-layer nonce is LSO-first; bt54 values are MSB-first
- **Rule:** `ll_nonce(counter, direction, iv)` writes packetCounter (39 bits) with directionBit as bit 7 of Nonce4,
  least significant octet first, then the 8-octet IV reversed. Pass the IV MSB-first; direction 1 = sent by the
  Central. `ll_aad` masks NESN, SN and MD (0xE3 keeps the rest) of the header's first octet.
- **Why:** Vol 6 Part E Tables 2.1 and 2.3; the Vol 6 Part C IV `0xDEAFBABEBADCAB24` appears in the sample nonces as
  `24abdcbabebaafde`. Replay (counter + 1) and reflection (other direction) both fail the MIC, which the tests show.
- **Where:** `src/bt54/ccm.py` `ll_nonce`, `ll_aad`; `tests/test_ccm.py`.

## Key material
- **Rule:** the Encrypted Data Key Material characteristic is 24 octets: session key (16) ‖ IV (8). Its permission is
  "Readable when authenticated and authorized" (Table 12.9): in practice a receiver pairs with the advertiser
  and reads it over an encrypted link.
- **Why:** Vol 3 Part C §12.6 (as cited by CSS §1.23) and the Bluetooth 5.4 technical overview (read 2026-11-10); permission text
  verified by Audit #1 (A1).
- **Where:** future `bt54` EAD module; `docs/ead.md`.

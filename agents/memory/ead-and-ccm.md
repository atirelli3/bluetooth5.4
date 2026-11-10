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
- **Why:** CSS v11 Part A §1.23 (read 2026-11-10).
- **Where:** future `bt54` EAD module + its tests.

## Brute-force loops catch InvalidTag, never ValueError
- **Rule:** `bt54.ccm.decrypt` raises `ccm.InvalidTag` (a `ValueError` subclass) only when the tag fails to verify,
  and a plain `ValueError` for bad parameters. Any key-search loop catches `ccm.InvalidTag` only.
- **Why:** with `except ValueError`, a wrong-length key or nonce fails on every candidate, the loop finds nothing,
  and the KNOB demo prints "key not found", a fake successful defence (silent-failure review 2026-11-10).
  Mutation check: with `hmac.compare_digest` forced to True, all 7 tamper tests fail.
- **Where:** `src/bt54/ccm.py` `decrypt`; `src/demo.py` `knob()` → the future KNOB scenario.

## Key material
- **Rule:** the Encrypted Data Key Material characteristic is 24 octets: session key (16) ‖ IV (8). Its permission is
  "Readable when authenticated and authorized" (Table 12.9): in practice a receiver pairs with the advertiser
  and reads it over an encrypted link.
- **Why:** Vol 3 Part C §12.6 (as cited by CSS §1.23) and the Bluetooth 5.4 technical overview (read 2026-11-10); permission text
  verified by Audit #1 (A1).
- **Where:** future `bt54` EAD module; `docs/resources/keyshare.md`.

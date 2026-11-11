# Crypto toolbox — memory

The Security Manager toolbox (`ah` not implemented; e, c1, s1, AES-CMAC, f4, f5, f6, g2, h6, h7): byte order, sample data, spec mapping.

## MSB-first inside f4–h7
- **Rule:** every multi-octet integer fed to AES-CMAC inside f4, f5, f6, g2, h6 and h7 is MSB-first, and so is the
  output. Appendix D writes its vectors the same way. Convert at the boundary when a value comes from or goes to an
  LSB-first PDU field.
- **Why:** Core v5.4 Vol 3 Part H §2.2 (read 2026-11-10 from the bluetooth.com HTML).
- **Where:** `src/bt54/toolbox.py`.

## Where the official vectors are
- **Rule:** take test vectors only from the spec. Vol 3 Part H Appendix D has D.1 AES-CMAC (RFC 4493), D.2 f4, D.3 f5,
  D.4 f6, D.5 g2, D.6 h6, D.7 ah, D.8 h7, and D.9–D.12 LTK ↔ link key (CT2=1 / CT2=0). c1 and s1 have inline examples
  in §2.2.3 / §2.2.4. LE encryption (CCM) sample data is in Vol 6 Part C §1.
- **Why:** user decision (B), official vectors are mandatory; section map read 2026-11-10. All of them pass (D.7 `ah`
  is not implemented yet). Vol 6 Part C §1 gives the SK = e(LTK, SKD) vector (formula: Vol 6 Part B §5.1.3.1) and 4 CCM packets; its CCM nonce is
  packetCounter (39 bits) + directionBit, then IV, LSO first.
- **Where:** `tests/test_toolbox.py`, `tests/test_ccm.py`.

## g2 is the 32-bit value; the 6 digits are the caller's
- **Rule:** `g2` returns AES-CMAC mod 2^32 (D.5: `0x2f9ed5ba`). The value the user compares is `g2 % 10**6`, shown
  zero-padded to 6 digits.
- **Why:** the 2024 code folded `mod 10^6` into g2, so it could not be checked against D.5, and it printed
  `63519` instead of `063519`.
- **Where:** `src/bt54/toolbox.py` `g2`; `src/bt54/pairing.py` `exchange` (`Exchange.number`).

## Cross-transport key conversion is h6/h7 composition
- **Rule:**
  - LTK → link key: `h6(h7(SALT"tmp1", LTK), "lebr")` with CT2=1, `h6(h6(LTK, "tmp1"), "lebr")` with CT2=0;
  - link key → LTK: `h6(h7(SALT"tmp2", LK), "brle")` with CT2=1, `h6(h6(LK, "tmp2"), "brle")` with CT2=0.

  SALT"x" is 12 zero octets followed by the 4 ASCII octets.
- **Why:** Appendix D.9–D.12 (the tests pass); this is the CTKD path that BLURtooth abuses.
- **Where:** `tests/test_toolbox.py` `test_cross_transport_key_conversion`; the future BLURtooth scenario.

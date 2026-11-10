# Crypto toolbox — memory

The Security Manager toolbox (e, ah, c1, s1, AES-CMAC, f4, f5, f6, g2, h6, h7): byte order, sample data, spec mapping.

## MSB-first inside f4–h7
- **Rule:** every multi-octet integer fed to AES-CMAC inside f4, f5, f6, g2, h6 and h7 is MSB-first, and so is the
  output. Appendix D writes its vectors the same way. Convert at the boundary when a value comes from or goes to an
  LSB-first PDU field.
- **Why:** Core v5.4 Vol 3 Part H §2.2 (read 2026-11-10 from the bluetooth.com HTML).
- **Where:** `src/bluetooth/bt_crypto_toolbox.py` (→ `src/bt54/`).

## Where the official vectors are
- **Rule:** take test vectors only from the spec. Vol 3 Part H Appendix D has D.1 AES-CMAC (RFC 4493), D.2 f4, D.3 f5,
  D.4 f6, D.5 g2, D.6 h6, D.7 ah, D.8 h7, and D.9–D.12 LTK ↔ link key (CT2=1 / CT2=0). c1 and s1 have inline examples
  in §2.2.3 / §2.2.4. LE encryption (CCM) sample data is in Vol 6 Part C §1.
- **Why:** user decision (B), official vectors are mandatory; section map read 2026-11-10. The inputs in
  `test/pairing/c1.py` / `s1.py` are the §2.2.3 / §2.2.4 examples (confirm the expected outputs through `spec`).
- **Where:** `tests/` (roadmap step 2).

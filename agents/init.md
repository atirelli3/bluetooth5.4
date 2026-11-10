# bluetooth5.4 — project init

**bluetooth5.4** = a Python simulation lab for Bluetooth LE security (Core v5.4): the crypto toolbox, LE pairing, AES-CCM,
Encrypted Advertising Data (EAD), and attacks on them. It started as the exam project of *Crittografia Applicata* 2024
(slides `docs/cpa.pdf`, 17 pp). Today it is a portfolio piece for cybersecurity / red team / VAPT job applications.

Read first, then `agents/memory/`, the last 3 `agents/handoff/` files, newest audit + review. The *why* of design
choices lives only in `agents/memory/` (grep by function/file/concept); user decisions in `agents/memory/decisions.md`.

## Goals (all four, in this order — user decision 2026-11-10)
1. **Correctness**: every primitive matches the spec's official sample data; the demo's bugs are fixed.
2. **Portfolio**: showcase README in English, `bt54` package, scenario CLI, CI badge, MIT licence, VAPT write-ups.
3. **Research**: EAD/PAwR implementation, plus new attacks: Legacy TK brute force (crackle-style), Method Confusion,
   BLURtooth (CTKD), EAD/CCM misuse.
4. **Reusable library**: `bt54` usable on its own, the CLI as its example.

## Requirements
- Python ≥ 3.12 (local pyenv 3.12.10; CI 3.12 + 3.13); `uv` (NOT installed yet on the Mac); `ruff`, `pytest`,
  `pytest-cov` as dev deps; one runtime dependency, `cryptography`.
- macOS only; GitHub `atirelli3/bluetooth5.4`; GitHub Actions. Simulation only, no hardware.

## Layout
Now (2024 code, untouched):
- `src/demo.py`: one script, runs at import. Covers Just Works (+MitM), Numeric Comparison (+MitM), LTK via f5/f6,
  LTK → BR/EDR link key via h6 (CT2=0), AES-CCM, and KNOB + the 7-octet fix.
- `src/bluetooth/`: `bt_crypto_toolbox.py` (f4 f5 f6 g2 h6, pycryptodome CMAC), `bt_ccm.py` (pycryptodome CCM
  wrapper, 16-octet tag), `bt_device.py` (`BTDevice`: P-256 keypair via `cryptography`, DHKey, IOCap, address).
- `test/`: exploration scripts, not pytest tests. `pairing/c1.py` and `s1.py` (inputs = the spec's inline examples),
  `f4.py` (duplicate of the toolbox), `encrypt/ccm.py` (hand-rolled CCM vs pycryptodome),
  `passkey.py` / `numeric_comparison.py` (FAKE sha256 stand-ins for c1/s1/f4/g2), `pk_coordinate.py`.
- `docs/resources/`: Italian/English study notes with TODOs (`keys.md`, `pairing/intro.md`, `pairing/phase1.md`
  are empty), `assets/` images; `docs/cpa.pdf` = 2024 slides (archive).
- `requirments.txt` (typo, pins cryptography 43.0.0 + pycryptodome 3.20.0); `README.md` in Italian.

Target (exact module split decided when building it, fewest files):
- `pyproject.toml` + `uv.lock`; `src/bt54/` (toolbox, pairing, CCM/EAD, device, attacks, `__main__.py` CLI);
  `tests/` (pytest, spec vectors); `docs/` (theory + `docs/attacks/<name>.md`); `.github/workflows/ci.yml`; `LICENSE`.

## Roadmap
1. **Tooling** (Plan Mode): pyproject + uv + ruff + pytest-cov; `src/bluetooth` → `src/bt54`; pycryptodome →
   `cryptography`; `requirments.txt` goes; CI workflow. → the push gate exists.
2. **Vectors**: tests for AES-CMAC (D.1), f4 f5 f6 g2 h6 h7 (D.2–D.8), LTK ↔ link key (D.9–D.12), c1/s1
   (§2.2.3–2.2.4), LE CCM (Vol 6 Part C §1); convert the `test/` scripts, delete the fakes and the duplicate.
3. **Audit #1**: confirm the known issues below, find the rest; fix what the user picks.
4. **CLI**: `python -m bt54 <scenario>|all`, expected vs actual, exit 0/1; `src/demo.py` goes.
5. **Portfolio**: README in English, CI badge, docs translated and completed.
6. **Research**: EAD (CSS Part A §1.23), then one attack at a time, each with its scenario + write-up.

## Known issues (found 2026-11-10; confirm in Audit #1)
- `just_work(mitm=True)` does not simulate a MitM. It swaps Bob's nonce inside a single pairing, so `Cb_mitm == Cb1`
  holds by construction, and the run then fails the f6 check because the two LTKs differ. The demo prints "MitM
  detected", which is the opposite of Just Works' real weakness (see `pairing.md`). Verified by running it.
- Numeric Comparison MitM block: `Nb = numeric_comparison(...)` would bind a tuple and `Na` is stale from the previous
  scenario (masked today because the call raises first). All scenarios reuse the same Alice/Bob key pairs.
- `g2` values are printed without zero-padding (`63519`, should read `063519`).
- `BTDevice.generate_random_bt_address` uses `random` and returns 7 random octets with an odd first octet. f5/f6
  expect A1/A2 as 56 bits (address type + 48-bit address): check the exact layout via `spec`.
- `knob()`: `entropy_reduction` rebinds its `MaxKeySize` argument, while `brute_force_ccm` reads the module global.
- The demo's CCM uses a 12-octet nonce and a 16-octet tag. LE uses a 13-octet nonce (EAD: Randomizer 5 ‖ IV 8) and a
  4-octet MIC.
- `test/encrypt/ccm.py` crashes on its own assert (B0 is built as 15 octets). It also pads PKCS-style instead of with
  zeros and handles AAD of 14 octets at most.
- `__pycache__` was tracked (removed from the index 2026-11-10); no `.gitignore` before that.

## Status
- 2026-11-10: bootstrap. CLAUDE.md, `agents/`, `.claude/` (subagents search/tests/docs/spec), LICENSE (MIT),
  `.gitignore`, README *Responsible use* added. No roadmap step started. Next: roadmap step 1.

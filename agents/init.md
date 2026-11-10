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
- Python ≥ 3.12 (local pyenv 3.12.10; CI 3.12 + 3.13); `uv` (0.13.7, Homebrew); `ruff`, `pytest`,
  `pytest-cov` as dev deps; one runtime dependency, `cryptography`.
- macOS only; GitHub `atirelli3/bluetooth5.4`; GitHub Actions. Simulation only, no hardware.

## Layout
Now (after roadmap steps 1–2):
- `src/bt54/`:
  - `toolbox.py`: e, AES-CMAC, c1, s1, f4, f5, f6, g2, h6, h7 on `cryptography`; raises ValueError on wrong lengths;
  - `ccm.py`: the hand-rolled RFC 3610 AES-CCM, AES-128, default 4-octet MIC, ValueError on a bad tag;
  - `device.py`: `BTDevice` (P-256 keypair, ECDH with the same-X check, IOCap, random static
    address, `pairing_address`) and `load_public_key` (off-curve → `InvalidPublicKey`).
- `tests/` (173 tests, 100% line + branch coverage):
  - `test_toolbox.py`: Appendix D D.1–D.6 and D.8–D.12, the c1/s1 examples, e via Vol 6 Part C, bad inputs;
  - `test_ccm.py`: the 4 Vol 6 Part C packets, AESCCM parity (encrypt + decrypt), tamper → `InvalidTag`, bad params;
  - `test_device.py`.
- `src/demo.py`: the 2024 script ported to `bt54` (`uv run python src/demo.py`); the CLI replaces it in step 4.
- `pyproject.toml` + `uv.lock` (runtime: `cryptography`; dev: pytest, pytest-cov, ruff); `.github/workflows/ci.yml`
  (the gate on 3.12 and 3.13, actions pinned by SHA, `UV_LOCKED=1`).
- `docs/resources/`: Italian/English study notes with TODOs (`pairing/intro.md`, `pairing/phase1.md`
  empty, `keys.md` a heading only), `assets/` images; `docs/cpa.pdf` = 2024 slides (archive); `README.md` in Italian.

Target (exact module split decided when building it, fewest files):
- `src/bt54/` gains pairing, EAD, attacks and the `__main__.py` CLI; `docs/attacks/<name>.md`; README in English.

## Roadmap
1. ~~**Tooling**~~ done 2026-11-10: uv + `pyproject.toml`, `bluetooth` → `bt54`, pycryptodome → `cryptography`, CI.
2. ~~**Vectors**~~ done 2026-11-10: every Appendix D vector except D.7 (`ah`, not implemented), the c1/s1 examples,
   and the Vol 6 Part C SK + CCM packets; `test/` and `requirments.txt` deleted.
3. ~~**Audit #1**~~ done 2026-11-10 (`agents/audits/2026-11-10-01.md`): L1–L4, T1–T10, A1–A6, D7 fixed.
4. **CLI**: `python -m bt54 <scenario>|all`, expected vs actual, exit 0/1; `src/demo.py` goes.
   Requirements: Audit #1 P1–P10 (two-party MitM pairings, KNOB masking the MSOs, LE floor of 7 octets,
   AuthReq from named flags with CT2 → h6/h7, message roles, SK = e(LTK, SKD) + LL nonce, typed errors).
5. **Portfolio**: README in English, CI badge, docs translated and completed. Inputs: Audit #1 D1–D11.
6. **Research**: EAD (CSS Part A §1.23), then one attack at a time, each with its scenario + write-up.
   Audit #1 R1 adds: LE key-size downgrade to 7 octets (the Max Encryption Key Size is not authenticated).

## Known issues (2026-11-10; Audit #1 P1–P10, fixed by the step-4 CLI)
- `just_work(mitm=True)` does not simulate a MitM. It swaps Bob's nonce inside a single pairing, so `Cb_mitm == Cb1`
  holds by construction, and the run then fails the f6 check because the two LTKs differ. The demo prints "MitM
  detected", which is the opposite of Just Works' real weakness (see `pairing.md`). Verified by running it.
- Numeric Comparison MitM block: `Nb = numeric_comparison(...)` would bind a tuple and `Na` is stale from the previous
  scenario (masked today because the call raises first). All scenarios reuse the same Alice/Bob key pairs.
- `knob()`: `entropy_reduction` rebinds its `MaxKeySize` argument, while `brute_force_ccm` reads the module global.
- Deferred from the 2026-11-10 reviews:
  - the legacy demo detects attacks with `assert`, which vanishes under `python -O`, and CI never runs the demo.
    Both go with the step-4 CLI (exit codes + tests);
  - Dependabot and `pip-audit` for the pinned actions and the lockfile belong to step 5.
- Kept on purpose: CI runs on every push (feature branches are merged locally, so there may be no PR) and uses
  ruff's defaults (0.17 already includes I and RUF).
- Fixed in steps 1–2:
  - g2 now returns the 32-bit value, and the demo shows it `mod 10^6` with 6 digits;
  - the demo's CCM uses a 13-octet nonce and a 4-octet MIC;
  - the broken hand-rolled CCM was rewritten and is tested;
  - `__pycache__` is untracked.

## Status
- 2026-11-10: bootstrap (CLAUDE.md, `agents/`, `.claude/`, LICENSE, `.gitignore`, README *Responsible use*).
- 2026-11-10: roadmap steps 1–2 done on `feat/tooling-and-vectors`; gate green locally and in CI (run 42910415051: 3.12 + 3.13, 154 passed, 99%)
  — merged to `main` (`64128fe`).
- 2026-11-10: Audit #1 done; the approved fixes are on `fix/audit-1` (173 tests, 100% line + branch coverage).
  Next: roadmap step 4 (CLI) in Plan Mode.

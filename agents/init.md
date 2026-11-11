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
Now (after roadmap steps 1–4):
- `src/bt54/`:
  - `toolbox.py`: e, AES-CMAC, c1, s1, f4, f5, f6, g2, h6, h7 on `cryptography`; raises ValueError on wrong lengths;
  - `ccm.py`: the hand-rolled RFC 3610 AES-CCM, AES-128, default 4-octet MIC, ValueError on a bad tag; `ll_nonce`
    and `ll_aad` build the LE link-layer nonce and AAD (Vol 6 Part E Tables 2.1, 2.3);
  - `device.py`: `BTDevice` (P-256 keypair, ECDH with the same-X check, `IOCap`, `AuthReq`, `max_key_size`, random
    static address, `pairing_address`) and `load_public_key` (off-curve → `InvalidPublicKey`);
  - `pairing.py`: LE Secure Connections Just Works + Numeric Comparison: `exchange` (key size, stage 1),
    `authenticate` (f5, Ea/Eb, masked LTK), `check_commit`, `mask_key`, `PairingFailed(reason)`;
  - `__main__.py`: the scenario CLI, `python -m bt54 <scenario>|all`: just-works, just-works-mitm,
    numeric-comparison, numeric-comparison-mitm, numeric-comparison-mitm-blind, knob-bredr, knob-le.
- `tests/` (280 tests, 100% line + branch coverage):
  - `test_toolbox.py`: Appendix D D.1–D.6 and D.8–D.12, the c1/s1 examples, e via Vol 6 Part C, bad inputs;
  - `test_ccm.py`: the 4 Vol 6 Part C packets, AESCCM parity (encrypt + decrypt), tamper → `InvalidTag`, bad params,
    `ll_nonce` / `ll_aad` against the sample nonces, replay and reflection;
  - `test_device.py`, `test_pairing.py` (spies pin the f6 arguments), `test_cli.py` (every scenario, exit codes).
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
4. ~~**CLI**~~ done 2026-11-11 on `feat/cli`: `python -m bt54 <scenario>|all`, 7 scenarios, `src/demo.py` deleted.
   Audit #1 P1–P10 met, except CT2 → h6/h7 (CTKD), which waits for BLURtooth in step 6 (CT2 stays 0 for now).
5. **Portfolio**: README in English, CI badge, docs translated and completed. Inputs: Audit #1 D1–D11; the P1
   correction (Just Works does run the Cb check, `decisions.md`); one write-up per scenario in `docs/attacks/`.
6. **Research**: EAD (CSS Part A §1.23), then one attack at a time, each with its scenario + write-up.
   - First: per-side message views + association-model selection from IOCap, built with Method Confusion
     (`pairing.md`, "known limit"): they let an attacker alter IOcap, addresses, Cb or nonces.
   - Audit #1 R1 adds: LE key-size downgrade to 7 octets (the Max Encryption Key Size is not authenticated).

## Known issues (2026-11-11)
- Known limits of the simulation (`pairing.md`; fixed in step 6, `decisions.md`):
  - the Cb, Ea and Eb checks read shared device objects, so they fail only through a DHKey mismatch: IOcap, address
    or nonce tampering cannot be modelled yet;
  - the association model is not chosen from IOCap (both devices must set SC, or `exchange` raises);
  - `knob-bredr` reuses the LE nonce size and AAD (framing simplified).
- Deferred: Dependabot and `pip-audit` for the pinned actions and the lockfile belong to step 5.
- Kept on purpose: CI runs on every push (feature branches are merged locally, so there may be no PR) and uses
  ruff's defaults (0.17 already includes I and RUF).
- Fixed in step 4: the 2024 demo's wrong models (P1–P5: Just Works and Numeric Comparison MitM, KNOB masking, the
  illegal 1-octet LE key, AuthReq), its `assert`-based detection, reused key pairs and dead code; `src/demo.py` is
  deleted. The CLI has no `assert`; `python -O -m bt54 all` passes.
- Fixed in steps 1–2: g2 returns the 32-bit value; the hand-rolled CCM was rewritten and is tested; `__pycache__`
  is untracked.

## Status
- 2026-11-10: bootstrap (CLAUDE.md, `agents/`, `.claude/`, LICENSE, `.gitignore`, README *Responsible use*).
- 2026-11-10: roadmap steps 1–2 done on `feat/tooling-and-vectors`; gate green locally and in CI (run 42910415051: 3.12 + 3.13, 154 passed, 99%)
  — merged to `main` (`64128fe`).
- 2026-11-10: Audit #1 done; the approved fixes are merged to `main` (`a0b7ee2`): 175 tests, 100% line + branch
  coverage, CI green on 3.12 and 3.13.
- 2026-11-11: roadmap step 4 done on `feat/cli` (pushed, not merged): CLI with 7 scenarios, `pairing.py`, LL nonce/AAD,
  `src/demo.py` deleted; reviewed by 4 ECC agents + 15 mutants killed; 280 tests, 100% line + branch coverage.
  Next: CI green on 3.12/3.13, merge to `main`, then roadmap step 5 (handoff 2026-11-11-01).

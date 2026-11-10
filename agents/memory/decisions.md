# Decisions — memory

Every user decision and every kept / rejected audit or review item, with its reason, grouped by area. Read it BEFORE
proposing a change or a cut so nothing already decided is re-proposed. Full registers live in `agents/audits/` and
`agents/reviews/`.

## How to use
- Search this file for the file / package / topic before flagging anything. A `[REJECTED]` or `[KEPT]` item can be
  reopened only with a fact that did not exist when it was decided; say so explicitly. A `[USER-YES]` is the user's
  decision: the decision is the reason, do not re-litigate.
- Tags: `[USER-YES]` user decision/approval. `[KEPT]` user answered NO/KEEP. `[REJECTED]` proposed, verified, stays.
  `[WHY]` load-bearing fact the code does not say. `[SUPERSEDED]` overtaken by a later decision.
  `(#N)` = audit/review N, `(#N #M)` = its finding M, `(B)` = bootstrap interview 2026-11-10.

## Project direction
- [USER-YES] (B) Goals: all four. That means completing the exam project, extending the research, building a reusable
  library, and making it a portfolio piece; the portfolio (cybersecurity / red team / VAPT job applications) is the main
  driver. Order: correctness → portfolio → research.
- [USER-YES] (B) Simulation only: no hardware, no radio, no BLE stack libraries. README carries a *Responsible use*
  section, CLAUDE.md a project rule.
- [USER-YES] (B) Attack roadmap besides KNOB and the Just Works MitM: Legacy TK brute force (crackle-style), Method
  Confusion, BLURtooth (CTKD), EAD/CCM misuse.
- [USER-YES] (B) Licence: MIT.

## Language and style
- [USER-YES] (B) English everywhere: CLAUDE.md, `agents/`, code, comments, docs, commits; the Italian 2024 docs are
  translated when touched.
- [USER-YES] (B) One short docstring per function with the spec reference and octet lengths/byte order; no
  line-by-line commentary; the why in `agents/memory/`. Deliberately NOT archx's strict "no rationale in code".
- [USER-YES] (B) Conventional Commits.

## Tooling and layout
- [USER-YES] (B) uv + `pyproject.toml` + ruff; Python ≥ 3.12; CI on GitHub Actions, Python 3.12 and 3.13.
- [USER-YES] (B) Package `bluetooth` → `bt54` (the old name shadows PyBluez's `bluetooth`).
- [USER-YES] (B) One crypto dependency, `cryptography` (ECDH P-256, AES, CMAC, AESCCM with a 4-octet tag; verified
  via context7 2026-11-10); pycryptodome goes. The hand-rolled CCM stays as a didactic implementation checked
  against AESCCM.
- [USER-YES] (B) Demo → scenario CLI `python -m bt54 <scenario>|all`, expected vs actual, exit 0/1.
- [USER-YES] (B) `test/` scripts: c1/s1 and the hand-rolled CCM move into `bt54` with pytest tests on spec vectors;
  `f4.py` (duplicate) and the sha256 fakes (`passkey.py`, `numeric_comparison.py`) are deleted; Audit #1 settles
  the details.
- [USER-YES] (B) Docs: one VAPT-style write-up per attack in `docs/attacks/` + theory docs + showcase README;
  `docs/cpa.pdf` stays as the 2024 archive.

## Quality gate
- [USER-YES] (B) Push gate = `ruff check` + `ruff format --check` + pytest with coverage ≥ 80% of `bt54`; CI runs the
  same line. [SUPERSEDED] by (#1 T4 T5): `scripts/gate.sh`, branch
  coverage ≥ 95%.
- [USER-YES] (B) The spec's official sample data is mandatory for every crypto primitive.
- [USER-YES] (B) `ecc:security-reviewer` after every change to crypto, pairing, CCM/EAD or attack code.

## Git and sessions
- [USER-YES] (B) Branching as in archx: session start asks for the branch; feature branches for big work; `main` only
  from green.
- [USER-YES] (B) No history rewrite: the 22 pre-bootstrap commits (16 named "saving") stay; clean from now on (`.gitignore`, `__pycache__`
  untracked); never force-push.
- [USER-YES] (B) Keywords: greetings (session start), `audit`, `review`, `demo`, `close session`.
- [USER-YES] (B) Models as in archx: `opusplan` + effort `high`; Haiku subagents `search`, `tests`, `docs`, `spec`.
- [USER-YES] (B) Full scaffold (CLAUDE.md, `agents/`, `.claude/`); memory split by area: crypto-toolbox, pairing,
  ead-and-ccm, attacks, testing-and-dev, decisions.

## Audit #1 (2026-11-10, `agents/audits/2026-11-10-01.md`)
- [USER-YES] (#1 L1–L4) Library fixes now:
  - random static address from `secrets`, plus `pairing_address`;
  - `InvalidPublicKey` (same X, and off-curve via `load_public_key`);
  - type hints, `compute_dh_key`, private key, `pK_y` and `nonce` dropped;
  - `_F5_SALT`, `_BLOCK`.
- [USER-YES] (#1 T1–T10) Tests and gate:
  - kill the 3 surviving mutants;
  - `scripts/gate.sh` is the gate's only copy, with branch coverage ≥ 95%;
  - accept-side boundary tests; the hook allows parametrized ids; `--strict-markers`; warnings are errors.
- [USER-YES] (#1 P1–P10) The demo is not patched: these rows are the requirements of the step-4 CLI scenarios.
- [USER-YES] (#1 R1) New attack in the research roadmap: LE key-size downgrade to 7 octets.
- [USER-YES] (#1 D1–D11) Inputs for the step-5 docs rewrite. D7 is applied now: the student ID is out of the README
  (the name stays).
- [USER-YES] (#1 A1–A6) `agents/` and `CLAUDE.md` drift fixed now.
- [REJECTED] (#1 post-fix review) A CI guard against an emptied `scripts/gate.sh` (grep for the threshold in CI).
  It would copy the gate line again, which undoes T4. In a single-maintainer repo every `gate.sh` change shows in
  the diff and the review, and the `tests` subagent cannot write files.
- [REJECTED] (#1 post-fix review) An explicit curve check in `compute_dh_key` for a peer key on another curve:
  `cryptography` already fails closed inside `exchange`; it can be added if a scenario needs the named error.

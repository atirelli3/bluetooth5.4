# Testing and dev — memory

The gate, pytest/coverage, the `tests` subagent and its hook, the local Python setup, dev-shell gotchas.

## The gate is scripts/gate.sh
- **Rule:** `bash scripts/gate.sh` runs ruff check, ruff format --check and pytest with `--cov=bt54 --cov-branch
  --cov-fail-under=95`. It is the gate's only copy: CI, the `tests` hook and CLAUDE.md all call it. Coverage flags
  stay in the script, not in `addopts`.
- **Why:**
  - Audit #1 T4/T5: the line had been copied into 4 places, and 80% line coverage left 19 points of slack;
  - `pytest-cov` applies `--cov-fail-under` to every run that collects coverage, so in `addopts` a single-file run
    would fail.
- **Where:** `scripts/gate.sh`, `.github/workflows/ci.yml`, `.claude/hooks/tests-only.sh`, `.claude/agents/tests.md`.

## Mutation-check crypto tests before trusting them
- **Rule:** patch the function under test in memory with a plausible bug, then run pytest. It must fail. Example:
  `uv run python -c "import bt54.toolbox as t, pytest; o = t.c1; t.c1 = lambda k, *a: o(bytes(16), *a);
  raise SystemExit(pytest.main(['-q', '-x', 'tests']))"`.
- **Why:** Audit #1 found 3 survivors: c1/s1 tested only with k = 0, f4 only with Z = 0, and a constant dhkey.
  Spec vectors built on zero keys hide key-handling bugs.
- **Where:** `tests/`.

## The scenario CLI is the demo
- **Rule:** `uv run python -m bt54 all` (or one scenario name) is the demo; it exits 1 on any expected/actual mismatch.
  Tests count the exact verdict lines (`"  PASS"`, `"  FAIL"`), never the substring.
- **Why:**
  - `FAIL` is a substring of `NUMERIC_COMPARISON_FAILED`, an expected outcome, so a substring count lies;
  - the scenarios are deterministic: `numeric-comparison-mitm` redraws a 6-digit collision (p = 10^-6), and the
    `knob-le` verdict uses an assumed rate, not the wall-clock sample (that one is only printed);
  - `src/demo.py` (2024) is deleted; its `assert`s vanished under `python -O`, the CLI has none (`python -O -m bt54 all`
    passes).
- **Where:** `src/bt54/__main__.py`, `tests/test_cli.py`.

## Other Python versions without touching .venv
- **Rule:** `UV_PROJECT_ENVIRONMENT=<scratch>/venv313 UV_PYTHON=3.13 UV_LOCKED=1 bash scripts/gate.sh` runs the
  gate on 3.13, the way the CI 3.13 job does.
- **Why:** without a separate `UV_PROJECT_ENVIRONMENT`, `UV_PYTHON` (or `uv run --python X`) rebuilds the project
  `.venv` on that version. The gate script calls `uv run` itself, so `uv run --isolated` around it does not help.
- **Where:** `.github/workflows/ci.yml` matrix.

## Fetching the spec from the shell
- **Rule:** `/usr/bin/curl -sL -A 'Mozilla/5.0' <bluetooth.com spec URL>`, then strip the HTML (python `re` +
  `html.unescape`) and slice by heading.
- **Why:** without a User-Agent bluetooth.com returns 105 bytes; the rtk hook rewrites a bare `curl` and truncates
  its output.
- **Where:** pulling sample data for new tests (2026-11-10: Appendix D, §2.2.3–2.2.4, Vol 6 Part C §1).

## Pushing workflow files needs the gh `workflow` scope
- **Rule:** git pushes through `gh auth git-credential`. A push that adds or changes `.github/workflows/*` needs
  the `workflow` scope on the token. The user grants it with `! gh auth refresh -h github.com -s workflow` (an
  interactive browser login).
- **Why:** on 2026-11-10 the first push of `ci.yml` was rejected: "refusing to allow an OAuth App to create or
  update workflow … without `workflow` scope". The scope has been granted since.
- **Where:** `.github/workflows/ci.yml`.

## Renames on macOS: python re, not sed
- **Rule:** do word-boundary renames with `python3` + `re.subn`, asserting the expected count (`(?<![A-Za-z0-9_])X\b`).
  Never use `sed '\b'`.
- **Why:** BSD sed has no `\b`. The `F5_SALT`/`BLOCK` rename half-applied silently and left a NameError (Audit #1
  L4, 2026-11-10).
- **Where:** any code rename in the repo.

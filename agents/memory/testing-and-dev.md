# Testing and dev — memory

The gate, pytest/coverage, the `tests` subagent and its hook, the local Python setup, dev-shell gotchas.

## The gate is one line
- **Rule:** `uv run ruff check . && uv run ruff format --check . && uv run pytest --cov=bt54 --cov-fail-under=80`.
  CI runs the same line on Python 3.12 and 3.13. Coverage flags stay on the command line, not in `addopts`;
  otherwise a single-file run would fail the 80% threshold.
- **Why:** user decision (B); `pytest-cov` applies `--cov-fail-under` to every run that collects coverage.
- **Where:** `CLAUDE.md` Push gate, `.claude/agents/tests.md`, `.claude/hooks/tests-only.sh` (allow-list regex: keep
  it in sync with the commands in `tests.md`).

## Running the legacy 2024 demo
- **Rule:** `uv run python src/demo.py` (it imports the installed `bt54`). The CLI replaces it in roadmap step 4.
- **Why:** since step 1 the demo runs on `bt54` + `cryptography`; pycryptodome is gone.
- **Where:** `src/demo.py`.

## Other Python versions without touching .venv
- **Rule:** `UV_LOCKED=1 uv run --isolated --python 3.13 pytest -q --cov=bt54 --cov-fail-under=80` mirrors the CI
  3.13 job.
- **Why:** `uv run --python X` without `--isolated` rebuilds the project `.venv` on that version.
- **Where:** `.github/workflows/ci.yml` matrix.

## Fetching the spec from the shell
- **Rule:** `/usr/bin/curl -sL -A 'Mozilla/5.0' <bluetooth.com spec URL>`, then strip the HTML (python `re` +
  `html.unescape`) and slice by heading.
- **Why:** without a User-Agent bluetooth.com returns 105 bytes; the rtk hook rewrites a bare `curl` and truncates
  its output.
- **Where:** pulling sample data for new tests (2026-11-10: Appendix D, §2.2.3–2.2.4, Vol 6 Part C §1).

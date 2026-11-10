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
- **Rule:** until roadmap step 1, run it from a throwaway venv in the scratchpad:
  `python3 -m venv <scratch>/venv && <scratch>/venv/bin/pip install -r requirments.txt`, then
  `cd src && PYTHONDONTWRITEBYTECODE=1 <scratch>/venv/bin/python demo.py`.
- **Why:** the code imports `Crypto` (pycryptodome), which is not in the local pyenv 3.12.10, and `uv` is not
  installed yet (2026-11-10). The flag keeps `__pycache__` out of the tree.
- **Where:** `src/demo.py`, `test/**/*.py`.

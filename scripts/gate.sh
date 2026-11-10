#!/usr/bin/env bash
# gate.sh — the push gate: lint, format, tests with branch coverage >= 95% of bt54 (CI runs this file).
set -euo pipefail
cd "$(dirname "$0")/.."
uv run ruff check .
uv run ruff format --check .
uv run pytest --cov=bt54 --cov-branch --cov-fail-under=95

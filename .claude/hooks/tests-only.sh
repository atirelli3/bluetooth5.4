#!/usr/bin/env bash
# tests-only.sh — PreToolUse guard of the tests subagent: only the approved test commands run.
cmd=$(jq -r '.tool_input.command')
gate='uv run ruff check \. && uv run ruff format --check \. && uv run pytest --cov=bt54 --cov-fail-under=80'
lint='uv run ruff (check|format --check) \.'
pyt='uv run pytest( tests/[A-Za-z0-9_/-]+\.py(::[A-Za-z0-9_]+)?)?'
demo='uv run python -m bt54 [a-z0-9-]+'
re="^($gate|$lint|$pyt|$demo)\$"
[[ $cmd =~ $re ]] && exit 0
echo "tests: not an approved test command: $cmd" >&2
exit 2

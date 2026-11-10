# bluetooth5.4 — project guide for Claude Code

**bluetooth5.4**: a Python simulation lab for Bluetooth LE security (Core v5.4). It covers the crypto toolbox, LE pairing
(Legacy + Secure Connections), AES-CCM, Encrypted Advertising Data, and attacks on them (KNOB, MitM, more on the roadmap).
It began as the 2024 *Crittografia Applicata* exam project and is now a red team / VAPT portfolio piece. Simulation only.
Details: `agents/init.md` (goals, layout, roadmap, status).

Precedence: this file > `agents/` > ECC rules (`~/.claude/rules/ecc/`) > plugin defaults.

## Keywords
Fire when the message is exactly the keyword (any case); the greetings also fire at the start of a longer message.

| Keyword | Does |
|---|---|
| `hello` `habibi yallah` `shalom` `ciao` | Session start |
| `audit` | Full audit → `agents/audits/` |
| `review` | Full review → `agents/reviews/` |
| `demo` | Run every scenario, report expected vs actual |
| `close session` | Handoff → push gate → commit → push |

### Session start
1. `git fetch origin --prune`, list the branches, **ask which branch to work on** (AskUserQuestion).
2. Dirty tree → stop and ask (never stash or discard). Clean → `git switch <branch>` + `git pull --ff-only`;
   not fast-forwardable → ask.
3. Load the context (keep it to ~5–10% of the window):
   - `agents/init.md`, in full;
   - `agents/memory/` headings, `awk '/^##/{if(FILENAME!=f){print "== "FILENAME;f=FILENAME}print}' agents/memory/*.md`
     (every heading is a rule); read the full topic file before working in its area;
   - the last 3 files in `agents/handoff/`;
   - the `## Summary` of the newest `agents/audits/` and `agents/reviews/` file, if any (the whole file if it has none).
4. Run `/ponytail:ponytail ultra`; load context7 + exa (ToolSearch
   `select:mcp__context7__resolve-library-id,mcp__context7__query-docs,mcp__plugin_exa_exa__web_search_exa,mcp__plugin_exa_exa__web_fetch_exa`).
   ECC hooks and rules load on their own. A session without a keyword still does this step before its first task.
5. Report in ≤5 lines: branch, HEAD vs origin, the last handoff's next steps, top open work.

### Every task
- **ponytail ultra** all session · **spec**: the Core Spec passage behind every primitive, field, constant and attack
  precondition · **context7**: the current docs of every library/tool the task touches (cryptography, pytest, uv, ruff) ·
  **exa**: in-depth web search for the rest (papers, CVEs, write-ups).
- **ECC** by task: `ecc:planner`/`ecc:architect` to plan · `ecc:tdd-guide` for fixes and features (RED → GREEN) ·
  `ecc:code-reviewer` + `ecc:silent-failure-hunter` + `ecc:python-reviewer` after each change · `ecc:security-reviewer`
  after every change to crypto, pairing, CCM/EAD or attack code · `ecc:refactor-cleaner` for cuts ·
  `ecc:doc-updater` for docs. Answer GateGuard's fact checks, never bypass them.

### Models (`.claude/settings.json`: `opusplan`, effort `high`)
- Use Plan Mode before new features, significant design tradeoffs, and bugs that survive the first attempted fix.
- **Opus plans**: Plan Mode runs Opus (root cause, design, audit/review synthesis); `/effort xhigh` for the hardest.
- **Sonnet implements**: outside Plan Mode the session runs Sonnet and writes the approved plan's code and docs.
- **Haiku supports** (`.claude/agents/`): `search` maps the repo, `tests` runs the approved test commands and reports
  failures, `docs` fetches library docs (context7, then exa), `spec` quotes the Core Spec / Supplement with
  Vol/Part/§. None of them edits files.

### Audit / Review
1. Read `agents/memory/decisions.md` in full: never re-propose an item already rejected or kept.
2. Whole codebase: `/ponytail:ponytail-audit` (audit) or `/ponytail:ponytail-review` (review), plus ECC agents in
   parallel, one slice each (crypto toolbox + CCM/EAD, pairing + attacks + CLI, `tests/`, docs + README + `agents/`):
   `ecc:code-reviewer`, `ecc:security-reviewer`, `ecc:silent-failure-hunter`, `ecc:python-reviewer`, plus
   `ecc:refactor-cleaner` (audit, report only) or the `ecc:code-review` skill + `ecc:pr-test-analyzer` (review).
   Every crypto claim checked against the spec (`spec`), every library claim against ctx7 + exa.
3. Hunt for bugs, spec deviations (byte order, field lengths, constants), gaps, over-engineering, horrible/unreadable
   code, dead code, missing tests or vectors, security holes (weak randomness, nonce reuse, non-constant-time compares),
   improvements.
4. Write the report. Change nothing until the user picks the findings; their verdicts go to `decisions.md`.

### Reports
- `agents/{handoff,audits,reviews}/yyyy-mm-dd-XX.md` — XX = 2-digit counter for that day in that folder.
- Audit/review number: one shared sequence, highest `#N` in audits + reviews, plus 1 (next **#1**). File:
  `# Audit #N — yyyy-mm-dd` (or `Review`), `## Summary` (≤10 lines: scope, counts, what's still open), then one row
  per finding: id, severity, `file:line`, problem, proposed fix, the user's verdict.
- Handoff ≤ 40 lines: what was done, branch + HEAD vs origin, gate results, open items, **next steps**, gotchas.

### Demo
`uv run python -m bt54 all` runs every scenario. Each scenario prints its expected and actual outcome, and the run
exits non-zero on any mismatch. Report per scenario: name, expected, actual, PASS/FAIL; read a failing scenario's code
before explaining it. Until the CLI lands (roadmap in `agents/init.md`), run the legacy `src/demo.py` the way
`agents/memory/testing-and-dev.md` says, and label the result as the legacy demo.

### Close session
1. Write the handoff. 2. Update `agents/init.md` (status, progress, open work) and the area's
`agents/memory/<topic>.md` (one Rule / Why / Where entry per new lesson). 3. Push gate; red → no push, report what
failed. 4. Commit everything (Conventional Commits) and push to the session's branch on `origin`; never force-push.

### Push gate
No push unless the gate is green:
`uv run ruff check . && uv run ruff format --check . && uv run pytest --cov=bt54 --cov-fail-under=80`
(lint, format, all tests, coverage ≥ 80% of `bt54`). GitHub Actions runs the same line on Python 3.12 and 3.13.
Until the gate exists (roadmap step 1), only changes to `CLAUDE.md`, `agents/`, `.claude/` and docs may be pushed.
Merge to `main` only from a green branch.

## KISS — keep it stupid simple
Simple logic, code and comments: human-readable, clean, lean. No abstraction, option or helper that isn't needed
today; boring over clever; delete before adding; the smallest diff that fixes the root cause.
**Docstrings, not commentary** (user decision): one short docstring per function giving what it computes, the spec
reference (`Vol 3 Part H §2.2.7`), and input/output lengths in octets with byte order. No line-by-line comments;
machine directives (`# noqa`) are fine. In tests the name says what is checked and the vector's spec reference goes in
the docstring or param id. The why of a design choice lives only in `agents/memory/`: grep it by concept before
touching an area, and treat odd lines (a byte reversal, a fixed key size, a skipped check) as load-bearing until it
says otherwise.

## Project rules
- **Simulation only** (user decision): no radio, no real devices, no BLE stack or sniffer libraries (bleak, PyBluez,
  scapy Bluetooth layers, Ubertooth/nRF tooling). Attacks run against simulated devices and the spec's sample data.
  The README keeps its *Responsible use* section.
- **The spec is the source of truth**: Core v5.4. That means Vol 3 Part H (Security Manager: toolbox §2.2, sample data
  Appendix D), Vol 6 Part E (LE link-layer security, CCM), Vol 6 Part C (LE sample data), and Vol 3 Part C §12.6
  (Encrypted Data Key Material), plus CSS v11 Part A §1.23 (Encrypted Data AD type). Fetch it through `spec`, never
  from memory.
- **Official vectors are mandatory**: no crypto function is done until a test checks it against the spec's sample data
  (Appendix D, the c1/s1 examples in §2.2.3–2.2.4, Vol 6 Part C). Hand-rolled primitives (the didactic CCM) are also
  checked against `cryptography`.
- One crypto dependency: `cryptography` (ECDH P-256, AES, CMAC, AESCCM); no pycryptodome. Keys, nonces, Randomizers
  and addresses come from `secrets` / `os.urandom`, never `random`.
- Every attack = one CLI scenario with a deterministic expected outcome + a VAPT-style write-up in `docs/attacks/`
  (threat model, preconditions, PoC scenario, impact, mitigation, spec/CVE references).
- Python ≥ 3.12, `uv` (pyproject + lock), `ruff`; English everywhere (code, docs, commits); Conventional Commits.
- Git: feature branches for big work, `main` = the green showcase; never force-push or rewrite history; nothing
  generated (`__pycache__`, `.venv`, coverage output) is committed.
- Box: macOS only (pyenv 3.12); CI = GitHub Actions.

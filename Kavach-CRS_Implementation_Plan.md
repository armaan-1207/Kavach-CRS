# Kavach-CRS — Implementation Plan (Submission-Stage PoC)

Scope: build the **core-build** items only (see Build Priority table in the solution doc) as a real, working loop. Everything else stays templated/stubbed and is labeled honestly as such in the ledger and report.

## Scope decision

- Primary track: **Python sample vulnerable app** — fastest to detect, patch, and prove against, and lines up directly with Bandit-class tooling.
- Secondary track: a **C stack-buffer-overflow** target with a minimal fuzz harness — added only after the Python loop is fully working end to end, since compiling/instrumenting native code adds setup risk that shouldn't block the main demo.

## Repo structure

```
kavach-crs/
├── target_app/            # deliberately vulnerable sample app (before)
├── target_app_patched/    # generated output after Kavach-CRS runs
├── detect/                # SAST + custom taint rules + reachability
├── reason/                # patch synthesis (CWE templates + optional LLM)
├── patch/                 # diff engine, backup, apply, rollback
├── prove/                 # PoV replay, differential check, regression check
├── gate/                  # confidence scoring
├── ledger/                # hash-chained JSON ledger + HTML report generator
├── cli.py                 # orchestrator entrypoint
└── run_output/             # ledger.json, report.html, backups/
```

## Build order

### Phase 1 — Target app
Write a small, deliberately vulnerable Flask/CLI app with 4–5 seeded bugs:
- [ ] SQL injection
- [ ] Command injection
- [ ] Path traversal
- [ ] Hardcoded credential
- [ ] (stub) stack buffer overflow — for the later C track

This is the fixed demo fixture. Get it solid first — everything downstream is measured against it.

### Phase 2 — DETECT
- [ ] Run Bandit as-is for standard findings
- [ ] Add a small custom AST-walker (Python `ast` module) for classes Bandit misses or under-reports (hardcoded secrets in config, path traversal via string concatenation)
- [ ] Normalize output into a single findings list: `{file, line, cwe, snippet}`

### Phase 3 — TRIAGE (reachability + mission-impact)
- [ ] Build a simple call-graph pass from the app's entry points (Flask routes / `main()`) to mark which functions are actually reachable
- [ ] Discard unreachable findings
- [ ] Add a hand-edited `mission_impact.yaml` (service name → tier) and use it to sort the remaining queue

Cheap to build, high demo value — you can show a finding get discarded live.

### Phase 4 — REASON
- [ ] Deterministic CWE-templates first:
  - Parameterized queries for SQLi
  - `shlex` / subprocess arg lists instead of `shell=True` for command injection
  - Path normalization + allowlist for traversal
  - Env-var lookup for hardcoded credentials
- [ ] Optional call to a hosted or local LLM for anything templates don't cover — templates should carry the demo, the LLM call is a fallback, not the headline

### Phase 5 — PATCH
- [ ] Generate a unified diff (`difflib`)
- [ ] Write a timestamped backup before overwriting
- [ ] Apply the patch
- [ ] Build the rollback function from day one, not bolted on later

### Phase 6 — PROVE
- [ ] **PoV replay**: re-run the detector against the patched file — the specific finding must be gone
- [ ] **Differential check**: hand-write a small input corpus (10–20 cases) per vulnerable function; run pre- vs. post-patch; outputs must match on all non-vulnerable-path cases
- [ ] **Regression check**: run existing tests if present; if none exist, explicitly log "no suite present" in the ledger rather than silently skipping

### Phase 7 — Confidence gate
- [ ] Simple, transparent weighted formula: diff line-count + differential-check pass rate + PoV-replay result
- [ ] Threshold decides auto-merge vs. flagged-for-review
- [ ] Keep the formula visible in the report — not a black box

### Phase 8 — Ledger + report
- [ ] Each stage appends a JSON entry containing `sha256(prev_entry + this_entry)`
- [ ] Render a single self-contained HTML report (Jinja2) showing findings, diffs, rationale, evidence, and trust scores

### Phase 9 — CLI wiring
- [ ] One command — `python cli.py run target_app/` — runs all phases in order and prints a summary
- [ ] This is the exact command run live in the demo

### Phase 10 — Dry run + polish
- [ ] Run the full loop multiple times end to end, fix rough edges
- [ ] Capture the real numbers (findings detected, patched count, time elapsed) for the Deliverables section — actual output, not projected

## Notes

- Every stubbed/templated piece (LLM fallback, mission-impact tags, reduced fuzz-cycle counts) should be labeled as such in the ledger/report output, not hidden — this matches the "build priority" framing already in the solution doc and holds up better under jury questioning.
- Don't start the C/fuzzing track until the Python loop runs cleanly start to finish at least once.

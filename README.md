# Kavach-CRS: Autonomous Self-Healing Infrastructure

**Kavach-CRS** is a lightweight, air-gapped Cyber Reasoning System (CRS) built for **AI Kavach / Terrier Cyber Quest 2026**. It autonomously **finds** vulnerabilities, **patches** them, and **proves** the fix holds — without cloud dependencies, without elevated privileges, and without causing mission downtime.

> **Runs in ~30 seconds on a standard laptop. Zero cloud required. Zero persistent services.**

---

## Why Kavach-CRS is Different

Every major CRS from DARPA AIxCC (Atlantis, Buttercup, FuzzingBrain) requires distributed GPU clusters, multi-agent cloud API pipelines, or Kubernetes orchestration. Kavach-CRS is built around the exact opposite philosophy:

| Capability | DARPA AIxCC Finalists | Kavach-CRS |
|---|---|---|
| Cloud LLM dependency | Required | Optional (Sovereign Mode blocks it by default) |
| Infrastructure needed | GPU cluster / Docker farm | Single laptop |
| Runtime | Minutes to hours | ~30 seconds |
| Air-gap deployable | No | Yes — runs fully offline via Ollama |
| Audit trail | Logging | Ed25519 cryptographic hash chain |
| Human operator loop | None | Commander Sign-off with signed ledger entries |

---

## Pipeline

Kavach-CRS runs a **9-stage, ledger-audited pipeline** for every scan:

| # | Stage | Module | What it does |
|---|-------|--------|---------------|
| 1 | **DETECT (Static)** | `detect/sast.py`, `detect/rules.py` | Bandit + custom AST taint rules (CWE-22, CWE-798) find candidate vulnerabilities |
| 2 | **DETECT (Dynamic)** | `detect/fuzzer.py` | Atheris fuzzes reachable entry points in a hardened subprocess, surfacing crashes static analysis misses *(Linux only)* |
| 3 | **TRIAGE** | `detect/triage.py` | Builds a call graph, discards findings in unreachable/dead code, ranks survivors by `mission_impact.yaml` tier |
| 4 | **REASON** | `reason/engine.py`, `reason/templates.py` | Deterministic CWE-keyed templates synthesize the fix first; an offline two-step LLM chain (RCA → Patch), RAG-grounded on MITRE ATT&CK mappings, is the fallback |
| 5 | **PATCH** | `patch/patcher.py` | Applies the minimal diff to a `.kavach_shadow` file atomically; timestamped backup taken before anything goes live |
| 6 | **PROVE (PoV)** | `prove/pov_replay.py` | Re-runs DETECT on the shadow file to confirm the specific finding is gone |
| 7 | **PROVE (Differential + Regression)** | `prove/differential.py`, `prove/regression.py` | Replays a safe+exploit corpus against pre/post-patch binaries in an isolated worker; runs existing pytest suite |
| 8 | **GATE** | `gate/scorer.py` | Transparent weighted confidence score → `AUTO_MERGE` / `HUMAN_REVIEW` / `REJECT`. LLM-generated patches are hard-capped at `HUMAN_REVIEW` regardless of score |
| 9 | **LEDGER + REPORT** | `ledger/ledger.py`, `ledger/report.py` | Every stage appended to an Ed25519-signed hash chain; rendered into a forensic HTML report |

---

## Key Features

### 🛡️ Sovereign Mode (Air-Gap Default)
Kavach-CRS monkey-patches `socket.socket.connect` at startup to block all outbound network calls by default. No data leaves the machine unless you explicitly pass `--allow-cloud-fallback`. Designed for classified / air-gapped military networks.

### 🤖 Gated LLM Fallback
When a deterministic template cannot handle a vulnerability pattern, Kavach-CRS falls back to a local LLM (via Ollama + Qwen2.5-Coder by default; production-ready for sovereign models like Sarvam-30B). The fallback is:
- **Scrubbed**: Secrets are masked before the snippet is sent
- **RAG-grounded**: Local MITRE ATT&CK mitigation data is injected into the prompt context
- **Hard-capped**: LLM-generated patches can never `AUTO_MERGE` — they are always routed to `HUMAN_REVIEW`

### 🔬 Differential Replay Sandbox
Every patch candidate is tested against a corpus of safe and malicious inputs in an isolated subprocess worker. This proves two things simultaneously:
- The **exploit is blocked** (expected behavior changed for attack inputs)
- **Normal behavior is preserved** (safe inputs still return correct results)

Plus metamorphic variants (URL percent-encoding, Unicode NFD) to catch evasion techniques.

### 📋 Tamper-Evident Audit Ledger
Every pipeline decision is appended to an **Ed25519 asymmetric signature chain**. Any third party can independently verify the full audit trail using only the published public key (`run_output/ledger_pub.pem`) — no trust in the tool itself required.

```bash
python cli.py verify run_output/ledger.json run_output/ledger_pub.pem
```

### 👮 Commander Sign-Off
Human operators can cryptographically approve or reject any `HUMAN_REVIEW` patch, with the decision permanently sealed into the ledger:
```bash
python cli.py approve F001 operator_callsign
python cli.py reject  F001 operator_callsign
```

### 🚀 Convoy Mode
Export and merge ledger bundles across isolated network nodes — signatures are verified before merging:
```bash
python cli.py export-ledger mission_ledger.zip
python cli.py merge-ledger incoming_node.zip
```

### 👁️ Active Defense Daemon
Watch a target directory and automatically re-run the full pipeline the moment any `.py` file changes:
```bash
python daemon.py target_app
```

---

## Getting Started

### Prerequisites
- Python 3.10+ (3.11 recommended on Linux for Atheris fuzzer support)
- For offline LLM fallback: [Ollama](https://ollama.com) with `ollama pull qwen2.5-coder`

### Quick Start (Windows)
```bat
kavach.bat target_app
```
Builds an isolated virtual environment, installs dependencies, and runs the scanner — no manual setup required.

### Standard Deployment (Linux / macOS)
```bash
pip install -r requirements.txt
python cli.py run target_app
```

### With Local LLM Fallback (Fully Offline)
```bash
# Install Ollama and pull the coder model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder

# Run with LLM fallback enabled (still fully offline — uses local Ollama)
python cli.py run target_app --allow-cloud-fallback
```

### With Cloud LLM Fallback (Optional)
```bash
export KAVACH_LLM_PROVIDER="gemini"
export GEMINI_API_KEY="your_key_here"
python cli.py run target_app --allow-cloud-fallback
```

### Reset Demo App Between Runs
Kavach-CRS patches files **in-place**. To restore the demo target to its vulnerable baseline:
```bash
git restore target_app/app.py
```

---

## Supported Vulnerability Classes

| CWE | Description | Detection | Template |
|---|---|---|---|
| CWE-89 | SQL Injection | Bandit B608 + AST | Parameterised query |
| CWE-78 | OS Command Injection | Bandit B602/B603 | List-based subprocess |
| CWE-22 | Path Traversal | Custom AST taint (concat + `os.path.join`) | `realpath` + containment check |
| CWE-798 | Hardcoded Credentials | Custom AST + Bandit B105-B108 | Environment variable |
| CWE-94 | Code Injection / Debug RCE | Bandit B201 | Env-controlled debug flag |
| CWE-502 | Insecure Deserialization | Bandit B301/B403 | LLM fallback |
| Any other | — | Bandit (all rules) | LLM fallback |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              KAVACH-CRS PIPELINE                │
│                                                 │
│  Target App                                     │
│      │                                          │
│      ▼                                          │
│  ┌────────┐   ┌────────┐   ┌──────────────┐    │
│  │ DETECT │──▶│ TRIAGE │──▶│    REASON    │    │
│  │Bandit+ │   │ CG +   │   │ Template →   │    │
│  │ AST +  │   │Mission │   │ LLM Fallback │    │
│  │Atheris │   │ Impact │   │ (Offline RAG)│    │
│  └────────┘   └────────┘   └──────┬───────┘    │
│                                   │             │
│  ┌────────────────────────────────▼──────────┐ │
│  │                  PATCH                    │ │
│  │   Shadow file → Atomic swap (os.replace)  │ │
│  └────────────────────────┬──────────────────┘ │
│                           │                     │
│  ┌────────────────────────▼──────────────────┐ │
│  │                  PROVE                    │ │
│  │  PoV Replay │ Differential │ Regression   │ │
│  │  (Isolated worker subprocess + corpus)    │ │
│  └────────────────────────┬──────────────────┘ │
│                           │                     │
│  ┌────────────────────────▼──────────────────┐ │
│  │              CONFIDENCE GATE              │ │
│  │  AUTO_MERGE │ HUMAN_REVIEW │ REJECT       │ │
│  │  (Transparent weighted formula)           │ │
│  └────────────────────────┬──────────────────┘ │
│                           │                     │
│  ┌────────────────────────▼──────────────────┐ │
│  │         Ed25519 TAMPER-EVIDENT LEDGER     │ │
│  │  + HTML Forensic Report + Commander CLI   │ │
│  └───────────────────────────────────────────┘ │
│                                                 │
│  ◀──── SOVEREIGN MODE: no outbound network ────▶│
└─────────────────────────────────────────────────┘
```

---

## Mission Impact Configuration

Operators configure vulnerability priority per-function via `mission_impact.yaml`:

```yaml
services:
  search: 1        # Tier 1: auth-critical — processed first
  admin: 1         # Tier 1: auth-critical
  ping:  2         # Tier 2: operational
  read_file: 2     # Tier 2: operational
  _default_tier: 2 # Fallback for unlisted functions
```

---

## Validated Architecture

1. **Parallel Execution** — multiple vulnerable files processed concurrently via `ThreadPoolExecutor`; sequential bottom-up within each file to prevent AST line-offset corruption
2. **Atomic Shadow Swap** — patches written to `.kavach_shadow` first; `os.replace()` atomically promotes to live only after PROVE passes
3. **Post-Patch Fuzzing** — Atheris re-fuzzes the patched route to confirm no new crashes introduced
4. **Bounded Risk, Not Blind Trust** — the Confidence Gate explicitly acknowledges APR overfitting theory (per *Undecidability of Overfitting in APR*) and bounds risk instead of claiming proof

---

## Known Limitations

- **Framework scope**: The call-graph reachability engine currently recognises Flask `@app.route`, `@app.before_request`, and generic `main()` entry points. Django and FastAPI support is on the roadmap.
- **Template coverage**: Deterministic templates cover the 5 most common Python web CWE classes. Unusual patterns fall to the LLM fallback (or `SKIPPED` in Sovereign Mode without Ollama).
- **Call-graph collision**: Bare method name matching (e.g., `execute`) can collide across namespaces in very large codebases. Fully-qualified name resolution is a planned enhancement.
- **Windows fuzzing**: Atheris requires Linux. On Windows, the pipeline gracefully skips the fuzzing stage and relies on static + LLM analysis. All other stages run identically.

---

## Performance Footprint

On the bundled `target_app` demo:
- **Full pipeline** (Detect → Report): ~30 seconds on a standard laptop
- **No persistent service** — exits cleanly after each run
- **No elevated privileges** required
- **8 pip dependencies** — `flask`, `bandit`, `cryptography`, `atheris`, `jinja2`, `pytest`, `pyyaml`, `watchdog`

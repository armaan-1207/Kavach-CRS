# Kavach-CRS: Autonomous Self-Healing Infrastructure

Kavach-CRS is a Cyber Reasoning System (CRS) built for the **AI Kavach** hackathon, inspired by state-of-the-art Automated Program Repair (APR) research. It autonomously **finds** vulnerabilities, **patches** them and **bounds risk** with transparent evidence - without causing mission downtime.

Kavach-CRS surgically rewrites vulnerable Python logic in-place, neutralizing exploits (SQLi, Command Injection, Path Traversal, Hardcoded Credentials and Flask Debug/RCE) while preserving 100% of normal system behavior.

---

## Pipeline

Kavach-CRS runs a nine-stage, ledger-audited pipeline for every scan:

| # | Stage | Module | What it does |
|---|-------|--------|---------------|
| 1 | **DETECT** | `detect/sast.py`, `detect/rules.py` | Bandit + custom AST taint rules find candidate vulnerabilities |
| 2 | **DETECT (dynamic)** | `detect/fuzzer.py` | Atheris fuzzes reachable Flask routes in a hardened subprocess, surfacing crashes static analysis misses |
| 3 | **TRIAGE** | `detect/triage.py` | Builds a call graph, discards findings in unreachable/dead code and ranks survivors by `mission_impact.yaml` tier |
| 4 | **REASON** | `reason/engine.py`, `reason/templates.py` | Deterministic CWE-keyed templates synthesize the fix first; an offline two-step LLM chain (RCA -> Patch, RAG-grounded on MITRE ATT&CK mappings) is the fallback, never the primary decision-maker |
| 5 | **PATCH** | `patch/patcher.py` | Applies the minimal diff, takes a timestamped backup before touching anything and supports rollback |
| 6 | **PROVE** | `prove/pov_replay.py`, `prove/differential.py`, `prove/regression.py` | Re-runs DETECT to confirm the specific finding is gone; replays a safe+exploit input corpus against pre-/post-patch binaries in an isolated worker process to prove behavior preservation and exploit neutralization; runs the existing pytest suite (or explicitly flags `NO_SUITE_PRESENT` and falls back to differential evidence) |
| 7 | **PROVE (post-patch fuzz)** | `detect/fuzzer.py` | Re-fuzzes the patched route to confirm no new crashes were introduced |
| 8 | **GATE** | `gate/scorer.py` | Transparent, weighted confidence score decides `AUTO_MERGE` / `HUMAN_REVIEW` / `REJECT`; LLM-generated patches and any run missing PoV/differential evidence are hard-capped at `HUMAN_REVIEW` regardless of score |
| 9 | **LEDGER + REPORT** | `ledger/ledger.py`, `ledger/report.py` | Every stage is appended to an Ed25519-signed hash chain (`run_output/ledger.json`) and rendered into a forensic HTML report (`run_output/report.html`) |

## Elite Features

- **Autonomous Patching**: Detects vulnerabilities via Bandit, custom AST rules and **Atheris Fuzzing** and applies correct source-code patches.
- **LLM Laced Fallback**: When standard patch templates miss a vulnerability, Kavach-CRS securely queries a Generative AI fallback to write the patch. LLM patches are mathematically capped at `HUMAN_REVIEW` by the Confidence Gate to ensure fail-safe autonomy.
- **Differential Replay Sandbox** - executes the patched code against a corpus of safe *and* malicious inputs, proving the exploit is blocked *and* safe behavior is preserved before ever considering AUTO_MERGE.
- **Sovereign, Air-Gapped Intelligence** - runs local-first with **Offline RAG** injecting MITRE ATT&CK mitigation guidance into a two-step LLM chain (RCA -> Patch). Defaults to **Qwen2.5-Coder** via Ollama; production-ready for indigenous sovereign models such as **Sarvam-30B**.
- **Active Defense Daemon** (`daemon.py`) - watches a target directory and re-runs the full pipeline the moment a `.py` file changes.
- **Tamper-Evident Ledger** - an Ed25519 asymmetric signature chain gives any third party an unforgeable, zero-trust audit trail using only the published public key (`run_output/ledger_pub.pem`). The private key is auto-generated locally and gitignored. In production, it should be stored in an HSM or separate write-once log shipper; the public key is pinned out-of-band at deploy time.
- **Bounded Risk, Not Blind Trust** - per APR overfitting theory, no finite test corpus proves general correctness. The Confidence Gate bounds risk instead of claiming proof and explicitly downgrades LLM-authored patches to human review.

## Getting Started

### 1. The Zero-Dependency Air-Gapped Bootstrapper (Windows)
*Requires Python 3.10+*
For instant deployment without dependency headaches, just run the bootstrapper:
```bat
kavach.bat target_app
```
This builds an isolated virtual environment, installs dependencies and runs the scanner - no manual setup required.
*(Note: Atheris fuzzing is notoriously difficult to compile natively on Windows. To maintain CI/CD resilience, the Kavach-CRS architecture gracefully catches this on Windows edge nodes and degrades to Static/LLM analysis without crashing. On Linux servers, it will actively fuzz the routes.)*

### 2. Standard Deployment
```bash
pip install -r requirements.txt
python cli.py run target_app
```

### 3. Continuous Active Defense (EDR Mode)
Monitor a directory indefinitely and auto-heal any vulnerability dropped by a developer (or attacker):
```bash
python daemon.py target_app
```

Check the final CISO overview in `run_output/report.html`.

### Resetting the Demo (Important!)
Kavach-CRS patches files **in place**. Running the pipeline a second time will naturally yield fewer/zero findings (the app is now secure). To re-run the live demo, restore the target app to its vulnerable baseline first:
```bash
git restore target_app/app.py
```

## Validated Architecture

This implementation follows strategies identified in post-mortems of major Automated Program Repair challenges:
1. **Parallel Execution** - processes multiple vulnerable files concurrently via ThreadPools (sequential bottom-up within a file to avoid AST offset corruption).
2. **Post-Patch Fuzzing** - validates patches with Atheris before gating.
3. **Bounded Risk vs. Proof** - a strict Confidence Gate bounds overfitting risk with deterministic logic, capping LLM-generated patches at `HUMAN_REVIEW` to guarantee fail-safe autonomy.

### 4. Independent Ledger Verification
To independently verify the cryptographic integrity of a generated ledger without running the whole pipeline:
```bash
python cli.py verify run_output/ledger.json run_output/ledger_pub.pem
```

## Known Demo Limitations & Caveats
- **"No Test Suite" Path**: The pipeline gracefully handles targets with missing test suites by prioritizing differential replay evidence (`NO_SUITE_PRESENT`). However, because the demo `target_app` includes `test_app.py`, this fallback path is not triggered live.
- **Call-Graph Matching**: The triage module maps function references across the target application. Currently, it uses bare function names, which works perfectly for the demo but would require fully qualified namespace matching for extreme enterprise scale.
- **OS Sandboxing Constraints**: Kavach-CRS is built for maximum cross-platform resilience. On Linux, the sandbox enforces strict POSIX `rlimit` containment (0 forks, capped memory). On Windows, POSIX `rlimit` is unavailable, so the worker degrades gracefully to Python-level stubbing. 

## Performance Footprint
The pipeline (Detect -> Reason -> Patch -> Sandbox Replay -> Prove -> Report) is designed for lightweight, in-process operation. On the bundled demo target, the full run typically completes in a single-digit number of seconds on a standard laptop, with no persistent service or elevated privileges required.

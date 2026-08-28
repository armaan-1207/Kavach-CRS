# Kavach-CRS: Autonomous Self-Healing Infrastructure

Kavach-CRS is a next-generation Cyber Reasoning System (CRS) inspired by State-of-the-Art Automated Program Repair. It is designed to autonomously find vulnerabilities, mathematically prove patch correctness and heal application source code logic **without causing mission downtime**.

Kavach-CRS surgically rewrites the vulnerable Python logic in-place, neutralizing exploits (like SQLi, Path Traversal and Command Injection) while preserving 100% of normal system functionality.

## Elite Features

- **No-Downtime Patching**: Neutralizes 0-days via AST manipulation without taking the application offline.
- **Differential Replay Sandbox**: We don't blindly trust AI. Kavach-CRS executes the patched code against a corpus of both safe and malicious inputs, proving mathematically that the exploit is blocked *and* safe behavior is preserved before merging.
- **Sovereign, Air-Gapped Intelligence**: Designed for military infrastructure, Kavach-CRS runs 100% offline. It features **Offline RAG** (Retrieval-Augmented Generation) that injects strict MITRE ATT&CK mitigation guidelines into a **Two-Step LLM Chain-of-Thought (RCA -> Patch)**.
- **Pluggable LLM Architecture**: Defaults to **Qwen2.5-Coder** via Ollama for blistering local speed and is production-ready for indigenous sovereign models like **Sarvam-30B**.
- **Active Defense Daemon (daemon.py)**: Kavach-CRS is an active EDR agent. Using a background daemon and parallel thread pools, it continuously monitors your fleet. The exact second a vulnerable line is saved, Kavach-CRS detects, patches and heals it in real time.
- **Tamper-Evident Ledger**: Uses an **Ed25519 asymmetric cryptographic signature chain** (un_output/ledger.json) to provide an unforgeable, zero-trust audit trail of the CRS's decisions.

## Getting Started

### 1. The Zero-Dependency Air-Gapped Bootstrapper (Windows)
For instant deployment without dependency headaches, just run the bootstrapper:
`at
kavach.bat target_app
`
*(This automatically builds an isolated virtual environment, installs dependencies and runs the fleet scanner in parallel).*

### 2. Standard Deployment
`ash
pip install -r requirements.txt
python cli.py run target_app
`

### 3. Continuous Active Defense (EDR Mode)
To monitor a directory indefinitely and auto-heal any vulnerabilities dropped by developers or attackers:
`ash
python daemon.py target_app
`

Check the final CISO overview in un_output/report.html.

### Resetting the Demo (Important!)
Because Kavach-CRS successfully applies patches directly to the target files on disk, running the pipeline a second time will naturally yield **0 findings** (since the app is now secure!). 
To run the demo again and watch it catch the vulnerabilities, restore the target app back to its vulnerable baseline first:
`ash
git restore target_app/app.py
`

## Validated Architecture
This version of Kavach-CRS implements the winning strategies identified in the post-mortems of major Automated Program Repair challenges:
1. **Parallel Execution**: Processes multiple vulnerable files concurrently using ThreadPools.
2. **Post-Patch Fuzzing**: Validates patches with Atheris before gating.
3. **Bounded Risk vs Proof**: A strict Confidence Gate that bounds the risk of patch overfitting using deterministic logic, explicitly capping LLM-generated patches at HUMAN_REVIEW to ensure fail-safe autonomy.

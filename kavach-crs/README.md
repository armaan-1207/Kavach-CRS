# Kavach-CRS

Kavach-CRS is a Cyber Reasoning System (CRS) designed to autonomously find vulnerabilities, generate patches, and prove their correctness through differential replay, confidence gating, and a cryptographically authenticated hash-chain ledger.

## Features

- **Autonomous Patching**: Detects vulnerabilities via Bandit, custom AST rules, and **Atheris Fuzzing**, and applies correct source-code patches.
- **Differential Replay**: Proves patches don't break functionality by executing both vulnerable and patched versions in an isolated sandbox and comparing results.
- **Confidence Gate**: A strict, mathematically sound gating system that computes a confidence score before classifying patches as AUTO_MERGE, HUMAN_REVIEW, or REJECT.
- **Tamper-Evident Ledger**: Uses an HMAC-signed SHA-256 ledger (un_output/ledger.json) backed by atomic file writes to provide an unforgeable audit trail of the CRS's decisions.
- **Defensive-By-Design Sandbox**: The worker.py module isolates untrusted execution by fully stubbing subprocess and OS-level execution commands and enforcing a hard timeout, preventing the CRS from being attacked by the code it analyzes.

## Getting Started

1. **(Optional) Install Fuzzer**: To enable Atheris fuzzing, run on a Linux environment (like Kali/Ubuntu) and install the fuzzer:
   ```bash
   pip install atheris
   ```
   *(On Windows, the CRS will safely skip the fuzzer stage and rely on static/dynamic analysis).*

2. Run the CRS against the provided demo target app:
   ```bash
   python cli.py run target_app/app.py
   ```

Check the final report in un_output/report.html.

## DevSecOps Hardened

This version of Kavach-CRS has undergone a comprehensive DevSecOps audit and implements strict isolation and tamper-proofing mechanisms that prioritize being **lightweight** over heavy virtualization:

1. **Kernel-Level Sandbox (`rlimit`)**: The target application is executed out-of-process with strict syscall-level `rlimit` containment (0 forks, capped CPU, capped RAM), preventing untrusted code from attacking the CRS without the overhead of Docker/VMs.
2. **Cryptographic Artifact Hashing**: The HMAC-signed ledger cryptographically chains not only the decision metadata but the exact SHA-256 byte hashes of the pre-patch backup and post-patch content, ensuring absolute tamper-evidence.
3. **Dynamic Single-Run Secrets**: The CRS eliminates local CWE-798 vulnerabilities by generating dynamic, cryptographic secrets per-run rather than relying on hardcoded test keys in the harness.
4. **Safety Caps**: Any skipped evidence forces a `HUMAN_REVIEW` downgrade, making the Confidence Gate mathematically fail-safe.
5. **Path Sanitization**: Local filesystem paths are scrubbed from the forensic reports to prevent PII leakage.

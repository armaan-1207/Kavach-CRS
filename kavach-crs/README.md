# Kavach-CRS

Kavach-CRS is a Cyber Reasoning System (CRS) designed to autonomously find vulnerabilities, generate patches, and prove their correctness through differential replay, confidence gating, and a cryptographically authenticated hash-chain ledger.

## Features

- **Autonomous Patching**: Detects vulnerabilities via Bandit and custom AST rules, and applies correct source-code patches.
- **Differential Replay**: Proves patches don't break functionality by executing both vulnerable and patched versions in an isolated sandbox and comparing results.
- **Confidence Gate**: A strict, mathematically sound gating system that computes a confidence score before classifying patches as AUTO_MERGE, HUMAN_REVIEW, or REJECT.
- **Tamper-Evident Ledger**: Uses an HMAC-signed SHA-256 ledger (un_output/ledger.json) backed by atomic file writes to provide an unforgeable audit trail of the CRS's decisions.
- **Defensive-By-Design Sandbox**: The worker.py module isolates untrusted execution by fully stubbing subprocess and OS-level execution commands and enforcing a hard timeout, preventing the CRS from being attacked by the code it analyzes.

## Getting Started

Run the CRS against the provided demo target app:

``bash
python cli.py run target_app/app.py
``

Check the final report in un_output/report.html.

## DevSecOps Hardened

This version of Kavach-CRS has undergone a DevSecOps audit and implements strict isolation and tamper-proofing mechanisms.

1. **Sandboxed Worker**: The target application is run out-of-process in a strictly limited environment.
2. **HMAC Ledger**: Set KAVACH_LEDGER_KEY or the CRS will generate a .ledger_key to sign the audit trail, preventing tampering.
3. **Safety Caps**: Any skipped evidence forces HUMAN_REVIEW.
4. **Path Sanitization**: Local filesystem paths are scrubbed from reports to prevent PII leakage.

"""
Dead code module — contains a vulnerable function that is NOT reachable
from any Flask route or main() entry point.

Purpose: demo the TRIAGE reachability filter discarding this finding live.
Kavach-CRS should detect the vulnerability here via SAST but then discard
it during triage because no entry point calls `legacy_export()`.
"""
import os
import subprocess


def legacy_export(user_input: str) -> str:
    """
    DEAD CODE — never called from any route or main().
    Vulnerable to command injection (CWE-78), but unreachable.
    Triage should discard this finding.
    """
    # VULN (intentional, unreachable): shell=True with user input
    out = subprocess.check_output(f"export_tool --target {user_input}", shell=True, text=True)
    return out

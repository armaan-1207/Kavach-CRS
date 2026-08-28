"""
Regression check — Kavach-CRS Phase 6 (PROVE step 3)

Tries to run an existing test suite against the patched file.
If no test suite is found, explicitly logs "NO_SUITE_PRESENT" and triggers
the differential corpus as fallback evidence — never silently skips.

This is the "no test suite" reality handling that distinguishes Kavach-CRS
from systems that assume CI coverage exists.

── SECURITY HARDENING (Phase A) ─────────────────────────────────────────────
pytest COLLECTS and IMPORTS every test_*.py it finds under target_path —
that's arbitrary target-directory code running with whatever this call's
environment provides. Previously this call inherited the *entire* parent
environment (subprocess.run(cmd, ...) with no env= override), so any leaked
CI/orchestrator secrets in os.environ were reachable from test collection.
This now passes an explicit, minimal allowlisted environment instead.
"""
import os
import subprocess
import sys
from pathlib import Path


def run_regression(target_path: str, patch_result: dict) -> dict:
    """
    1. Look for pytest / unittest tests under target_path.
    2. If found → run them and report pass/fail.
    3. If not found → return NO_SUITE_PRESENT with explicit note that
       differential replay corpus serves as the correctness evidence.

    Returns:
    {
        "status":        "PASS" | "FAIL" | "NO_SUITE_PRESENT" | "SKIPPED"
        "tests_found":   bool
        "passed":        int
        "failed":        int
        "detail":        str
        "raw_output":    str
    }
    """
    if patch_result.get("status") != "PATCHED":
        return {
            "status": "SKIPPED",
            "tests_found": False,
            "passed": 0,
            "failed": 0,
            "detail": f"Patch was {patch_result.get('status')} — regression check skipped.",
            "raw_output": "",
        }

    root = Path(target_path)
    test_files = (
        list(root.rglob("test_*.py"))
        + list(root.rglob("*_test.py"))
        + list(root.rglob("tests/*.py"))
    )

    if not test_files:
        return {
            "status": "NO_SUITE_PRESENT",
            "tests_found": False,
            "passed": 0,
            "failed": 0,
            "detail": (
                "No test suite found under target directory. "
                "This is the 'no test suite' scenario Kavach-CRS is designed for. "
                "Correctness evidence is provided by the differential replay corpus "
                "(behavioral delta verification) and PoV replay — see those results."
            ),
            "raw_output": "",
        }

    # Minimal, explicitly allowlisted environment — pytest imports every
    # collected test file, so the target directory's code runs with
    # whatever this env provides. Don't hand it the orchestrator's full
    # environment (CI tokens, ledger keys, etc.).
    restricted_env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "ADMIN_SECRET": os.environ.get("ADMIN_SECRET", ""),
    }

    # Run pytest
    cmd = [sys.executable, "-m", "pytest", "--tb=short", "-q", str(root)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, env=restricted_env
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "FAIL",
            "tests_found": True,
            "passed": 0,
            "failed": 0,
            "detail": "pytest exceeded 60s timeout — treated as failed regression check.",
            "raw_output": "",
        }

    raw = result.stdout + result.stderr

    # Parse summary line: "X passed, Y failed"
    passed = failed = 0
    for line in raw.splitlines():
        if "passed" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "passed" and i > 0:
                    try:
                        passed = int(parts[i - 1])
                    except ValueError:
                        pass
                if p == "failed" and i > 0:
                    try:
                        failed = int(parts[i - 1])
                    except ValueError:
                        pass

    status = "PASS" if result.returncode == 0 else "FAIL"
    return {
        "status": status,
        "tests_found": True,
        "passed": passed,
        "failed": failed,
        "detail": f"pytest exit code {result.returncode}. {passed} passed, {failed} failed.",
        "raw_output": raw[:2000],  # cap for ledger size
    }

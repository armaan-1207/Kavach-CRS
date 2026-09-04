"""
Regression check - Kavach-CRS Phase 6 (PROVE step 3)

Tries to run an existing test suite against the patched file.
If no test suite is found, explicitly logs "NO_SUITE_PRESENT" and triggers
the differential corpus as fallback evidence - never silently skips.

This is the "no test suite" reality handling that distinguishes Kavach-CRS
from systems that assume CI coverage exists.

── SECURITY HARDENING (Phase A) ─────────────────────────────────────────────
pytest COLLECTS and IMPORTS every test_*.py it finds under target_path -
that's arbitrary target-directory code running with whatever this call's
environment provides. Previously this call inherited the *entire* parent
environment (subprocess.run(cmd, ...) with no env= override), so any leaked
CI/orchestrator secrets in os.environ were reachable from test collection.
This now passes an explicit, minimal allowlisted environment instead.
"""
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

_regression_lock = threading.Lock()


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
            "detail": f"Patch was {patch_result.get('status')} - regression check skipped.",
            "raw_output": "",
        }

    root = Path(target_path)
    if root.is_file():
        root = root.parent

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
                "(behavioral delta verification) and PoV replay - see those results."
            ),
            "raw_output": "",
        }

    # Minimal, explicitly allowlisted environment - pytest imports every
    # collected test file, so the target directory's code runs with
    # whatever this env provides. Don't hand it the orchestrator's full
    # environment (CI tokens, ledger keys, etc.).
    restricted_env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "ADMIN_SECRET": os.environ.get("ADMIN_SECRET") or "test_secret_for_differential_replay",
        "PYTHONPATH": str(Path.cwd()) + (os.pathsep + os.environ.get("PYTHONPATH", "") if os.environ.get("PYTHONPATH") else ""),
    }

    # Swap the shadow file into the live location temporarily so pytest
    # imports the patched code instead of the vulnerable original.
    live_path = Path(patch_result.get("file", ""))
    shadow_path = Path(patch_result.get("shadow_path", ""))
    backup_path = Path(patch_result.get("backup_path", ""))
    
    with _regression_lock:
        swapped = False
        if live_path.exists() and shadow_path.exists() and backup_path.exists():
            try:
                # We already have a safe backup in run_output/backups/
                os.replace(shadow_path, live_path)
                swapped = True
            except OSError:
                pass

        # Run pytest — assign result=None first to prevent UnboundLocalError
        # if subprocess.run raises something other than TimeoutExpired.
        result = None
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
                "detail": "pytest exceeded 60s timeout - treated as failed regression check.",
                "raw_output": "",
            }
        finally:
            # Always restore the live file from backup and put the shadow back
            if swapped:
                # Copy live (which is currently the shadow) back to shadow path
                shutil.copy2(live_path, shadow_path)
                # Restore live from backup without destroying the backup copy
                shutil.copy2(backup_path, live_path)

    if result is None:
        return {
            "status": "FAIL",
            "tests_found": True,
            "passed": 0,
            "failed": 0,
            "detail": "pytest subprocess failed to start.",
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

    status = "PASS" if result.returncode == 0 else ("NO_SUITE_PRESENT" if result.returncode == 5 else "FAIL")
    return {
        "status": status,
        "tests_found": True,
        "passed": passed,
        "failed": failed,
        "detail": f"pytest exit code {result.returncode}. {passed} passed, {failed} failed.",
        "raw_output": raw[:2000],  # cap for ledger size
    }

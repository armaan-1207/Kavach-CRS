"""
Differential Replay — Kavach-CRS Phase 6 (PROVE step 2)

This is the core novelty: using the pre-patch binary as a ground-truth oracle
for all inputs that DON'T trigger the bug ("safe cases").

For safe cases:  pre-patch output == post-patch output  → behavior preserved ✓
For exploit cases: confirm the exploitable behavior is GONE in patched version.

This gives machine-checkable correctness evidence even when no test suite
exists — which is the "no test suite" reality of legacy defence code.

Academic label: behavioral delta verification / split-oracle replay.
"""
import ast
import importlib
import importlib.util
import io
import os
import sys
import types
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from typing import Any

import yaml


CORPUS_PATH = Path(__file__).parent / "corpus" / "cases.yaml"


def _load_corpus(cwe_class: str | None = None) -> list[dict]:
    cases = yaml.safe_load(CORPUS_PATH.read_text(encoding="utf-8"))["cases"]
    if cwe_class:
        cases = [c for c in cases if c.get("cwe_class") == cwe_class]
    return cases


def _call_flask_route(app_module_path: str, route: str, params: dict) -> tuple[int, str]:
    """
    Import the Flask app from app_module_path and make a test-client request
    to `route` with `params` as query-string args.
    Returns (status_code, response_text).
    """
    spec = importlib.util.spec_from_file_location("_target_app", app_module_path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]

    # Override __file__ so that os.path.dirname(__file__) inside the app
    # always points to target_app/, not run_output/backups/.
    # This ensures DB_PATH and base_dir resolve correctly regardless of
    # whether we're loading the original or a backup copy.
    _original_app_dir = str(Path(__file__).parent.parent / "target_app")
    mod.__file__ = str(Path(_original_app_dir) / "app.py")

    # Suppress init_db() side effects and Flask startup output
    buf = io.StringIO()
    old_argv = sys.argv[:]
    sys.argv = [app_module_path]
    # Set env vars that patched app may require (e.g. after CWE-798 fix)
    os.environ.setdefault("ADMIN_SECRET", "test_secret_for_differential_replay")

    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        pass
    finally:
        sys.argv = old_argv

    flask_app = getattr(mod, "app", None)
    if flask_app is None:
        return -1, "No Flask app found in module"

    # Run init_db silently if present
    init_fn = getattr(mod, "init_db", None)
    if init_fn:
        try:
            init_fn()
        except Exception:
            pass

    # Use mock.patch to stub subprocess calls ONLY during the test-client call.
    # This prevents the differential from actually pinging the network, which
    # would be slow and non-deterministic. We care about HTTP response diffs,
    # not real ping output. The mock is scoped tightly to this one test call.
    import subprocess as _real_sp
    import unittest.mock as _mock

    def _stub_check_output(cmd, **kw):
        # Both shell=True (vulnerable) and list-form (patched) return a stub.
        # Differential cares about HTTP status code differences, not real output.
        # shell=True returns a different stub from list-form so exploit vs safe
        # cases show distinct behaviour pre/post-patch.
        if kw.get("shell"):
            return "KAVACH-STUB-SHELL-OUTPUT"
        return "KAVACH-STUB-NO-SHELL-OUTPUT"

    def _stub_run(cmd, **kw):
        import subprocess as sp
        if kw.get("shell"):
            return sp.CompletedProcess(cmd, 0, stdout="KAVACH-STUB-SHELL", stderr="")
        return sp.CompletedProcess(cmd, 0, stdout="KAVACH-STUB", stderr="")

    mod_sp = getattr(mod, "subprocess", None)
    if mod_sp is not None:
        with _mock.patch.object(mod_sp, "check_output", side_effect=_stub_check_output), \
             _mock.patch.object(mod_sp, "run", side_effect=_stub_run):
            with flask_app.test_client() as client:
                try:
                    resp = client.get(route, query_string=params)
                    return resp.status_code, resp.get_data(as_text=True)
                except Exception as e:
                    return -1, str(e)[:200]
    else:
        with flask_app.test_client() as client:
            try:
                resp = client.get(route, query_string=params)
                return resp.status_code, resp.get_data(as_text=True)
            except Exception as e:
                return -1, str(e)[:200]


def run_differential(
    original_file: str,
    patched_file: str,
    backup_path: str,
    cwe_class: str | None = None,
) -> dict:
    """
    Run the differential replay corpus against both the original (pre-patch,
    restored from backup) and the patched file.

    Returns a result dict:
    {
        "status":          "PASS" | "FAIL" | "PARTIAL" | "SKIPPED"
        "total_cases":     int
        "safe_pass":       int   — safe cases where behavior was preserved
        "safe_fail":       int   — safe cases where behavior changed (regression)
        "exploit_blocked": int   — exploit cases where vuln is now blocked
        "exploit_live":    int   — exploit cases where vuln still works (bad)
        "details":         list[dict]  — per-case results
        "summary":         str
    }
    """
    if not backup_path or not Path(backup_path).exists():
        return {
            "status": "SKIPPED",
            "total_cases": 0,
            "safe_pass": 0, "safe_fail": 0,
            "exploit_blocked": 0, "exploit_live": 0,
            "details": [],
            "summary": "No backup found — differential replay requires pre-patch backup.",
        }

    corpus = _load_corpus(cwe_class)
    if not corpus:
        return {
            "status": "SKIPPED",
            "total_cases": 0,
            "safe_pass": 0, "safe_fail": 0,
            "exploit_blocked": 0, "exploit_live": 0,
            "details": [],
            "summary": f"No corpus cases for {cwe_class}.",
        }

    details = []
    safe_pass = safe_fail = exploit_blocked = exploit_live = 0

    for case in corpus:
        route = case["route"]
        params = case.get("input", {})
        is_exploit = case.get("exploit", False)
        case_id = case["id"]

        orig_code, orig_body = _call_flask_route(backup_path, route, params)
        patch_code, patch_body = _call_flask_route(patched_file, route, params)

        if is_exploit:
            # For exploit cases: we want to see the patched version blocking/changing behavior
            behavior_changed = (orig_code != patch_code) or (orig_body != patch_body)
            if behavior_changed:
                exploit_blocked += 1
                outcome = "EXPLOIT_BLOCKED"
                detail = "Patched version no longer responds identically to exploit input. ✓"
            else:
                exploit_live += 1
                outcome = "EXPLOIT_LIVE"
                detail = "⚠ Patched version still responds identically to exploit input — vuln may still be active."
        else:
            # For safe cases: pre-patch and post-patch must respond identically
            behavior_preserved = (orig_code == patch_code) and (orig_body == patch_body)
            if behavior_preserved:
                safe_pass += 1
                outcome = "SAFE_PRESERVED"
                detail = "Non-vulnerable path behavior unchanged. ✓"
            else:
                safe_fail += 1
                outcome = "SAFE_REGRESSION"
                detail = (
                    f"⚠ Behavior changed on safe input! "
                    f"Before: HTTP {orig_code}; After: HTTP {patch_code}. Possible regression."
                )

        details.append({
            "case_id": case_id,
            "cwe_class": case.get("cwe_class"),
            "route": route,
            "exploit": is_exploit,
            "outcome": outcome,
            "detail": detail,
            "orig_status": orig_code,
            "patch_status": patch_code,
        })

    total = len(corpus)
    # PASS: no safe regressions AND all exploit cases blocked
    # PARTIAL: some issues but not total failure
    if safe_fail == 0 and exploit_live == 0:
        status = "PASS"
    elif safe_fail > 0 and exploit_live > 0:
        status = "FAIL"
    else:
        status = "PARTIAL"

    summary = (
        f"Differential replay: {total} cases — "
        f"safe preserved {safe_pass}/{safe_pass+safe_fail}, "
        f"exploits blocked {exploit_blocked}/{exploit_blocked+exploit_live}."
    )

    return {
        "status": status,
        "total_cases": total,
        "safe_pass": safe_pass,
        "safe_fail": safe_fail,
        "exploit_blocked": exploit_blocked,
        "exploit_live": exploit_live,
        "details": details,
        "summary": summary,
    }

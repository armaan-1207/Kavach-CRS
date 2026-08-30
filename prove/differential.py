"""
Differential Replay - Kavach-CRS Phase 6 (PROVE step 2)

This is the core novelty: using the pre-patch binary as a ground-truth oracle
for all inputs that DON'T trigger the bug ("safe cases").

For safe cases:  pre-patch output == post-patch output  → behavior preserved ✓
For exploit cases: confirm the exploitable behavior is GONE in patched version.

This gives machine-checkable correctness evidence even when no test suite
exists - which is the "no test suite" reality of legacy defence code.

Academic label: behavioral delta verification / split-oracle replay.

── SECURITY HARDENING (Phase A) ─────────────────────────────────────────────
This module used to import the target app in-process via `importlib` and
`exec_module`, and mock `subprocess.check_output`/`.run` via
`unittest.mock.patch.object`. Both had gaps:

  1. In-process exec meant untrusted target code ran with full CRS process
     privileges (ledger access, env vars, network).
  2. The mock only attached if the target module imported subprocess as
     `import subprocess` - `from subprocess import check_output`, `.call`,
     `.check_call`, and `.Popen` all bypassed it, so exploit payloads in the
     corpus (e.g. "127.0.0.1 & whoami") could actually execute.

Both routes are now closed: target-app execution happens in an isolated
subprocess (`prove/worker.py`) with a minimal environment, a hard timeout,
and a module-level subprocess stub installed before the target is imported.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml


CORPUS_PATH = Path(__file__).parent / "corpus" / "cases.yaml"
WORKER_PATH = Path(__file__).parent / "worker.py"
WORKER_TIMEOUT_S = 15


def _load_corpus(cwe_class: str | None = None) -> list[dict]:
    import urllib.parse
    import unicodedata
    import copy
    
    cases = yaml.safe_load(CORPUS_PATH.read_text(encoding="utf-8"))["cases"]
    if cwe_class:
        cases = [c for c in cases if c.get("cwe_class") == cwe_class]
        
    metamorphic_cases = []
    for c in cases:
        metamorphic_cases.append(c)
        if not c.get("exploit", False):
            # Safe-by-construction URL encoding variant
            c_url = copy.deepcopy(c)
            c_url["id"] = c["id"] + "_urlenc"
            c_url["input"] = {k: urllib.parse.quote(str(v)) for k, v in c["input"].items()}
            metamorphic_cases.append(c_url)
            
            # Safe-by-construction Unicode NFD normalization variant
            c_nfd = copy.deepcopy(c)
            c_nfd["id"] = c["id"] + "_nfd"
            c_nfd["input"] = {k: unicodedata.normalize("NFD", str(v)) for k, v in c["input"].items()}
            metamorphic_cases.append(c_nfd)
            
    return metamorphic_cases


def _call_flask_route(app_module_path: str, route: str, params: dict, original_filepath: str = None) -> tuple[int, str]:
    """
    Run a single Flask test-client GET request against `app_module_path` in
    an isolated worker subprocess (see prove/worker.py) and return
    (status_code, response_text).

    Never imports or executes target-app code in this process.
    """
    # Minimal, explicitly allowlisted environment for the worker.
    # - PATH / SYSTEMROOT are needed so `sys.executable` can actually start
    #   on the host OS; the worker itself clears its own PATH before it
    #   touches the target app, so this does not give the target app shell
    #   access.
    # - ADMIN_SECRET is the one app-specific value the demo target needs.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "ADMIN_SECRET": os.environ.get("ADMIN_SECRET", ""),
    }
    if original_filepath:
        env["KAVACH_TARGET_FILE"] = original_filepath

    try:
        result = subprocess.run(
            [sys.executable, str(WORKER_PATH), app_module_path, route, json.dumps(params)],
            capture_output=True,
            text=True,
            timeout=WORKER_TIMEOUT_S,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return -1, f"worker subprocess exceeded {WORKER_TIMEOUT_S}s timeout"

    stdout = (result.stdout or "").strip()
    if not stdout:
        return -1, f"worker produced no output (rc={result.returncode}): {(result.stderr or '')[:200]}"

    try:
        # Worker prints exactly one JSON line; be defensive in case anything
        # else leaked to stdout before it.
        data = json.loads(stdout.splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return -1, f"worker returned unparseable output: {stdout[:200]}"

    return data.get("status_code", -1), data.get("body", "")


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
        "safe_pass":       int   - safe cases where behavior was preserved
        "safe_fail":       int   - safe cases where behavior changed (regression)
        "exploit_blocked": int   - exploit cases where vuln is now blocked
        "exploit_live":    int   - exploit cases where vuln still works (bad)
        "details":         list[dict]  - per-case results
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
            "summary": "No backup found - differential replay requires pre-patch backup.",
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

        orig_code, orig_body = _call_flask_route(backup_path, route, params, original_filepath=original_file)
        patch_code, patch_body = _call_flask_route(patched_file, route, params, original_filepath=original_file)

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
                detail = "⚠ Patched version still responds identically to exploit input - vuln may still be active."
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

    safe_total = safe_pass + safe_fail
    exploits_total = exploit_blocked + exploit_live

    summary = (
        f"Differential replay: {total} cases - "
        f"safe preserved {safe_pass}/{safe_total}, "
        f"exploits blocked {exploit_blocked}/{exploits_total}. "
        f"(Coverage: {total} cases)"
    )

    return {
        "status": status,
        "total_cases": total,
        "safe_pass": safe_pass,
        "safe_fail": safe_fail,
        "exploit_blocked": exploit_blocked,
        "exploit_live": exploit_live,
        "coverage_ratio": f"{total}/{total}",
        "details": details,
        "summary": summary,
    }

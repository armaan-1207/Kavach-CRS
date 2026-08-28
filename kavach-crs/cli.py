"""
Kavach-CRS CLI -- Phase 9 orchestrator

Usage:
    python cli.py run target_app/

Runs the full detect -> triage -> reason -> patch -> prove -> gate -> ledger -> report
pipeline and prints a summary.
"""
import sys
import io
import time
import uuid
from pathlib import Path

# Fix Windows console encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Stage imports ────────────────────────────────────────────────────────────
from detect.sast import run_detection
from detect.triage import run_triage
from reason.engine import reason_all
from patch.patcher import apply_patch
from prove.pov_replay import pov_replay
from prove.differential import run_differential
from prove.regression import run_regression
from gate.scorer import score as gate_score
from ledger.ledger import append as ledger_append
from ledger.report import generate_report

MISSION_IMPACT_PATH = "mission_impact.yaml"
BANNER = """
+----------------------------------------------------------+
|          KAVACH-CRS  --  Cyber Reasoning System          |
|     Autonomous Vulnerability Detection & Patching        |
|     Terrier Cyber Quest 2026  |  Air-Gapped Build        |
+----------------------------------------------------------+
""".strip()


def _sep(title: str = "") -> None:
    w = 60
    if title:
        pad = (w - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * (w - pad - len(title) - 2)}")
    else:
        print("─" * w)


def _ok(msg: str)   -> None: print(f"  ✓  {msg}")
def _warn(msg: str) -> None: print(f"  ⚠  {msg}")
def _err(msg: str)  -> None: print(f"  ✗  {msg}")
def _info(msg: str) -> None: print(f"     {msg}")


def run(target_path: str) -> None:
    import os
    from pathlib import Path
    os.environ["KAVACH_TARGET_ROOT"] = str(Path(target_path).parent.resolve())
    
    t_start = time.monotonic()
    run_id = str(uuid.uuid4())[:8]

    # Fix: Ensure a dynamic, per-run secret for differential replay instead of a hardcoded string
    import secrets
    import os
    run_secret = os.environ.get("ADMIN_SECRET") or secrets.token_hex(16)
    os.environ["ADMIN_SECRET"] = run_secret

    print(BANNER)
    print(f"\nTarget  : {Path(target_path).resolve()}")
    print(f"Run ID  : {run_id}")
    print(f"Mission : {MISSION_IMPACT_PATH}")

    run_summary: dict = {
        "run_id": run_id,
        "target": target_path,
        "items": [],
        "discarded": [],
        "stats": {},
    }

    # ── PHASE 1 & 2: DETECT ─────────────────────────────────────────────────
    _sep("DETECT")
    from detect.sast import run_detection
    from detect.triage import build_reachability
    from detect.fuzzer import run_atheris_fuzzer

    findings = run_detection(str(target_path))
    
    reachable = build_reachability(str(target_path))
    
    fuzz_findings = run_atheris_fuzzer(str(target_path), reachable)
    findings.extend(fuzz_findings)

    print(f"  Bandit + custom AST rules + Fuzzer: {len(findings)} raw findings")
    ledger_append("DETECT", {"count": len(findings), "findings": [
        {k: v for k, v in f.items() if k != "snippet"} for f in findings
    ]})

    # ── PHASE 3: TRIAGE ──────────────────────────────────────────────────────
    _sep("TRIAGE")
    survivors, discarded = run_triage(
        findings, target_path, mission_impact_path=MISSION_IMPACT_PATH
    )
    run_summary["discarded"] = discarded
    print(f"  Active (reachable + prioritised): {len(survivors)}")
    print(f"  Discarded (unreachable):           {len(discarded)}")
    for d in discarded:
        _warn(f"DISCARDED {d.get('id','?')} [{d.get('cwe','')}] "
              f"{Path(d.get('file','')).name}:{d.get('line','')} — {d.get('triage_reason','')}")
    ledger_append("TRIAGE", {
        "survivors": len(survivors),
        "discarded": len(discarded),
        "discarded_ids": [d.get("id") for d in discarded],
    })

    # ── PHASES 4-7: PER-FINDING LOOP ─────────────────────────────────────────
    counts = dict(patched=0, pov_pass=0, auto_merge=0, human_review=0, reject=0, skipped=0)

    # Sort bottom-to-top within each file so earlier patches don't shift line
    # numbers for later findings in the same file.
    survivors_ordered = sorted(
        survivors,
        key=lambda f: (f.get("file", ""), -f.get("line", 0))
    )

    
    import concurrent.futures
    import threading
    from itertools import groupby

    print_lock = threading.Lock()

    def process_finding(finding):
        local_item = {"finding": finding}
        local_logs = []
        fid = finding.get("id", "?")
        cwe = finding.get("cwe", "")
        
        local_logs.append(lambda: _sep(f"{fid}  {cwe}"))
        local_logs.append(lambda: _info(f"{Path(finding.get('file','')).name}:{finding.get('line','')}  "
              f"[{finding.get('severity','')}]  fn:{finding.get('enclosing_function','?')}  "
              f"tier:{finding.get('mission_tier','?')}"))
        local_logs.append(lambda: _info(finding.get("snippet", "")[:100]))

        # REASON
        patch_spec = reason_all([finding])[0]
        local_item["patch_spec"] = patch_spec
        if patch_spec.get("status") == "TEMPLATE_MISS":
            local_logs.append(lambda: _warn(f"REASON: template miss - {patch_spec.get('rationale','')}"))
        else:
            local_logs.append(lambda: _ok(f"REASON: patch generated for {cwe}"))

        # PATCH
        patch_result = apply_patch(patch_spec)
        local_item["patch"] = patch_result
        if patch_result["status"] == "PATCHED":
            local_logs.append(lambda: _ok(f"PATCH:  applied  ({len(patch_result.get('unified_diff', '').splitlines())} diff lines)  backup-> {Path(patch_result['backup_path']).name}"))
        elif patch_result["status"] == "SKIPPED":
            local_logs.append(lambda: _warn(f"PATCH:  skipped - {patch_result.get('reason', '')}"))
        else:
            local_logs.append(lambda: _err(f"PATCH:  error - {patch_result.get('reason', '')}"))

        # PROVE - PoV replay
        pov_result = pov_replay(patch_result, finding)
        local_item["pov"] = pov_result
        if pov_result["status"] == "PASS":
            local_logs.append(lambda: _ok(f"PROVE PoV:   {pov_result['detail']}"))
        elif pov_result["status"] == "FAIL":
            local_logs.append(lambda: _err(f"PROVE PoV:   {pov_result['detail']}"))
        else:
            local_logs.append(lambda: _warn(f"PROVE PoV:   {pov_result['detail']}"))

        # PROVE - Differential replay
        diff_result = run_differential(
            original_file=finding.get("file", ""),
            patched_file=finding.get("file", ""),
            backup_path=patch_result.get("backup_path", ""),
            cwe_class=cwe,
        )
        local_item["differential"] = diff_result
        
        def _diff_log():
            marker = _ok if diff_result["status"] == "PASS" else (_warn if diff_result["status"] == "PARTIAL" else _err)
            marker(f"PROVE Diff:  {diff_result['summary']}")
        local_logs.append(_diff_log)

        # PROVE - Regression check
        reg_result = run_regression(target_path, patch_result)
        local_item["regression"] = reg_result
        if reg_result["status"] == "NO_SUITE_PRESENT":
            local_logs.append(lambda: _warn(f"PROVE Reg:   {reg_result['detail'][:100]}"))
        elif reg_result["status"] == "PASS":
            local_logs.append(lambda: _ok(f"PROVE Reg:   {reg_result['detail']}"))
        else:
            local_logs.append(lambda: _err(f"PROVE Reg:   {reg_result['detail']}"))

        # PROVE - Post-patch Fuzzing
        post_fuzz_findings = run_atheris_fuzzer(str(target_path), {finding["fn"]} if finding.get("fn") else set())
        if post_fuzz_findings is None:
            post_fuzz_result = {"status": "SKIPPED", "detail": "Fuzzer not installed."}
            local_logs.append(lambda: _warn(f"PROVE Fuzz:  {post_fuzz_result['detail']}"))
        elif len(post_fuzz_findings) == 0:
            post_fuzz_result = {"status": "PASS", "detail": "Post-patch fuzzing found 0 crashes."}
            local_logs.append(lambda: _ok(f"PROVE Fuzz:  {post_fuzz_result['detail']}"))
        else:
            post_fuzz_result = {"status": "FAIL", "detail": f"Fuzzer found {len(post_fuzz_findings)} crashes post-patch!"}
            local_logs.append(lambda: _err(f"PROVE Fuzz:  {post_fuzz_result['detail']}"))
        local_item["post_fuzz"] = post_fuzz_result

        # GATE - Confidence scoring
        gate_result = gate_score(pov_result, diff_result, reg_result, patch_result, post_fuzz_result)
        local_item["gate"] = gate_result
        decision = gate_result["decision"]
        score_val = gate_result["score"]
        
        if decision == "AUTO_MERGE":
            local_logs.append(lambda: _ok(f"GATE:  score={score_val:.2f}  -> AUTO_MERGE v"))
        elif decision == "HUMAN_REVIEW":
            local_logs.append(lambda: _warn(f"GATE:  score={score_val:.2f}  -> HUMAN_REVIEW /!\  (evidence bundle attached in report)"))
        else:
            local_logs.append(lambda: _err(f"GATE:  score={score_val:.2f}  -> REJECT x"))

        return local_item, local_logs, patch_result, pov_result, decision

    def process_file_group(file_group):
        # We process findings in the same file sequentially (bottom-up) to avoid AST offset corruption
        results = []
        for finding in file_group:
            results.append(process_finding(finding))
        return results

    # Group by file
    findings_by_file = []
    for k, g in groupby(survivors_ordered, key=lambda f: f.get("file", "")):
        findings_by_file.append(list(g))

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_group = {executor.submit(process_file_group, fg): fg for fg in findings_by_file}
        for future in concurrent.futures.as_completed(future_to_group):
            try:
                group_results = future.result()
                with print_lock:
                    for local_item, local_logs, patch_result, pov_result, decision in group_results:
                        for log_fn in local_logs:
                            log_fn()
                        
                        run_summary["items"].append(local_item)
                        if patch_result["status"] == "PATCHED": counts["patched"] += 1
                        if patch_result["status"] == "SKIPPED": counts["skipped"] += 1
                        if pov_result["status"] == "PASS": counts["pov_pass"] += 1
                        
                        if decision == "AUTO_MERGE": counts["auto_merge"] += 1
                        elif decision == "HUMAN_REVIEW": counts["human_review"] += 1
                        else: counts["reject"] += 1

                        fid = local_item["finding"].get("id", "?")
                        cwe = local_item["finding"].get("cwe", "")
                        ledger_append(f"FINDING_{fid}", {
                            "finding_id": fid,
                            "cwe": cwe,
                            "patch_status": patch_result["status"],
                            "gate_decision": decision,
                            "gate_score": local_item["gate"]["score"]
                        })
            except Exception as e:
                with print_lock:
                    print(f"Error processing file group: {e}")


    # ── PHASE 8: REPORT ──────────────────────────────────────────────────────
    elapsed = round(time.monotonic() - t_start, 1)
    run_summary["stats"] = {
        "total_findings": len(findings),
        "triaged": len(survivors),
        "discarded": len(discarded),
        "patched": counts["patched"],
        "pov_pass": counts["pov_pass"],
        "auto_merge": counts["auto_merge"],
        "human_review": counts["human_review"],
        "reject": counts["reject"],
        "elapsed_s": elapsed,
    }

    # Sanitize paths in the report summary to avoid leaking absolute paths
    cwd = str(Path.cwd())
    def _sanitize(obj):
        if isinstance(obj, dict):
            return {k: _sanitize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_sanitize(item) for item in obj]
        elif isinstance(obj, str) and cwd in obj:
            try:
                return str(Path(obj).relative_to(cwd))
            except ValueError:
                return obj.replace(cwd, ".")
        return obj
        
    sanitized_summary = _sanitize(run_summary)
    report_path = generate_report(sanitized_summary)

    _sep("SUMMARY")
    print(f"""
  Total findings detected : {len(findings)}
  After triage (active)   : {len(survivors)}
  Discarded (unreachable) : {len(discarded)}
  Patched                 : {counts['patched']}
  PoV replay PASS         : {counts['pov_pass']}
  AUTO_MERGE              : {counts['auto_merge']}
  HUMAN_REVIEW            : {counts['human_review']}
  REJECT / SKIPPED        : {counts['reject'] + counts['skipped']}
  Elapsed                 : {elapsed}s
  Report                  : {report_path}
  Ledger                  : run_output/ledger.json
""")

    # Chain integrity check at the end
    from ledger.ledger import verify_chain
    ok, msg = verify_chain()
    if ok:
        _ok(f"Ledger chain verified — {msg}")
    else:
        _err(f"Ledger chain BROKEN — {msg}")

    print()


def main() -> None:
    if len(sys.argv) < 3 or sys.argv[1] != "run":
        print("Usage: python cli.py run <target_path>")
        sys.exit(1)
        
    target = Path(sys.argv[2]).resolve()
    crs_root = Path(__file__).parent.resolve()
    
    if not target.exists():
        print(f"Error: target path '{target}' does not exist.")
        sys.exit(1)
        
    # Self-preservation: Do not allow targeting our own CRS directory root or above
    if target == crs_root or target in crs_root.parents:
        print("Error: Target path cannot be the CRS directory or a parent of it.")
        sys.exit(1)
        
    run(str(target))


if __name__ == "__main__":
    main()

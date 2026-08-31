"""
Kavach-CRS CLI - Phase 9 orchestrator

Usage:
    python cli.py run target_app/

Runs the full detect -> triage -> reason -> patch -> prove -> gate -> ledger -> report
pipeline and prints a summary.
"""
import sys
import socket

_allow_cloud = "--allow-cloud-fallback" in sys.argv
_no_sovereign = "--no-sovereign-mode" in sys.argv

if not _allow_cloud and not _no_sovereign:
    _original_connect = socket.socket.connect
    def _sovereign_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ('127.0.0.1', 'localhost', '::1'):
            raise Exception(f"SecurityError: Sovereign Mode blocked outbound network call to {host}")
        return _original_connect(self, address)
    socket.socket.connect = _sovereign_connect


import io
import time
import uuid
from pathlib import Path

# Fix Windows console encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# - Stage imports ------------------------------------------------------------
from detect.sast import run_detection
from detect.triage import run_triage
from reason.engine import reason_all
from patch.patcher import apply_patch, swap_shadow, cleanup_shadow
from prove.pov_replay import pov_replay
from prove.differential import run_differential
from prove.regression import run_regression
from gate.scorer import score as gate_score
from ledger.ledger import append as ledger_append
from ledger.report import generate_report

MISSION_IMPACT_PATH = "mission_impact.yaml"
BANNER = """\033[38;5;39;1m
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    \033[38;5;21;1m██╗  ██╗ █████╗ ██╗   ██╗█████╗  ██████╗ ██╗  ██╗\033[38;5;39;1m         ║
║    \033[38;5;27;1m██║ ██╔╝██╔══██╗██║   ██║██╔══██╗██╔════╝██║  ██║\033[38;5;39;1m         ║
║    \033[38;5;33;1m█████╔╝ ███████║██║   ██║███████║██║     ███████║\033[38;5;39;1m         ║
║    \033[38;5;39;1m██╔═██╗ ██╔══██║╚██╗ ██╔╝██╔══██║██║     ██╔══██║\033[38;5;39;1m         ║
║    \033[38;5;45;1m██║  ██╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╗██║  ██║\033[38;5;39;1m         ║
║    \033[38;5;51;1m╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\033[38;5;39;1m         ║
║                                                              ║
║   \033[38;5;255;1mCYBER REASONING SYSTEM (CRS) \033[38;5;196;1m[ v1.0.0-Airgap ]             \033[38;5;39;1m║
║   \033[38;5;255;1mAutonomous Vulnerability Detection & Patching              \033[38;5;39;1m║
║   \033[38;5;255;1mTerrier Cyber Quest 2026                                   \033[38;5;39;1m║
╚══════════════════════════════════════════════════════════════╝\033[0m
""".strip()


def _sep(title: str = "") -> None:
    w = 60
    if title:
        pad = (w - len(title) - 2) // 2
        print(f"\n{'-' * pad} {title} {'-' * (w - pad - len(title) - 2)}")
    else:
        print("-" * w)


def _ok(msg: str)   -> None: print(f"  ✓  {msg}")
def _warn(msg: str) -> None: print(f"  ⚠  {msg}")
def _err(msg: str)  -> None: print(f"  ✗  {msg}")
def _info(msg: str) -> None: print(f"     {msg}")


def run(target_path: str, allow_cloud_fallback: bool = False) -> None:
    import os
    from pathlib import Path
    p = Path(target_path).resolve(); os.environ["KAVACH_TARGET_ROOT"] = str(p if p.is_dir() else p.parent)
    
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

    # - PHASE 1 & 2: DETECT -------------------------------------------------
    _sep("DETECT")
    
    # Autonomous Corpus Generation for unknown targets
    target_app_file = Path(target_path) / "app.py"
    if target_app_file.exists():
        try:
            from prove.autocorpus import build_dynamic_corpus
            dyn_path = Path("run_output/dynamic_corpus.yaml")
            build_dynamic_corpus(str(target_app_file), str(dyn_path))
            print("  ►  Autocorpus: generated dynamic behavioral tests for target routes.")
        except Exception as e:
            _warn(f"Autocorpus generation failed: {e}")

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

    # - PHASE 3: TRIAGE ------------------------------------------------------
    _sep("TRIAGE")
    survivors, discarded = run_triage(
        findings, target_path, mission_impact_path=MISSION_IMPACT_PATH, reachable=reachable
    )
    run_summary["discarded"] = discarded
    print(f"  Active (reachable + prioritised): {len(survivors)}")
    print(f"  Discarded (unreachable):           {len(discarded)}")
    for d in discarded:
        _warn(f"DISCARDED {d.get('id','?')} [{d.get('cwe','')}] "
              f"{Path(d.get('file','')).name}:{d.get('line','')} - {d.get('triage_reason','')}")
    ledger_append("TRIAGE", {
        "survivors": len(survivors),
        "discarded": len(discarded),
        "discarded_ids": [d.get("id") for d in discarded],
    })

    # - PHASES 4-7: PER-FINDING LOOP -----------------------------------------
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

        # Capture all finding fields by value to avoid lambda closure race conditions
        local_logs.append(lambda fid=fid, cwe=cwe: _sep(f"{fid}  {cwe}"))
        _fname = Path(finding.get("file", "")).name
        _fline = finding.get("line", "")
        _fsev  = finding.get("severity", "")
        _ffunc = finding.get("enclosing_function", "?")
        _ftier = finding.get("mission_tier", "?")
        _fsnip = finding.get("snippet", "")[:100]
        local_logs.append(lambda n=_fname, l=_fline, s=_fsev, f=_ffunc, t=_ftier: _info(
            f"{n}:{l}  [{s}]  fn:{f}  tier:{t}"))
        local_logs.append(lambda snip=_fsnip: _info(snip))

        # REASON
        patch_spec = reason_all([finding], allow_cloud_fallback)[0]
        local_item["patch_spec"] = patch_spec
        _ps_status = patch_spec.get("status")
        _ps_rat    = patch_spec.get('rationale','')
        if _ps_status == "TEMPLATE_MISS":
            local_logs.append(lambda r=_ps_rat: _warn(f"REASON: template miss - {r}"))
        else:
            local_logs.append(lambda c=cwe: _ok(f"REASON: patch generated for {c}"))

        # PATCH
        patch_result = apply_patch(patch_spec)
        local_item["patch"] = patch_result
        _pr_status = patch_result["status"]
        _pr_diff_lines = len(patch_result.get('unified_diff', '').splitlines())
        _pr_backup = Path(patch_result.get('backup_path', 'unknown')).name
        _pr_reason = patch_result.get('reason', '')
        if _pr_status == "PATCHED":
            local_logs.append(lambda dl=_pr_diff_lines, bp=_pr_backup: _ok(
                f"PATCH:  applied  ({dl} diff lines)  backup-> {bp}"))
        elif _pr_status == "SKIPPED":
            local_logs.append(lambda r=_pr_reason: _warn(f"PATCH:  skipped - {r}"))
        else:
            local_logs.append(lambda r=_pr_reason: _err(f"PATCH:  error - {r}"))

        # PROVE - PoV replay
        shadow_file = patch_result.get("shadow_path") or patch_result.get("file", "")
        # temporarily trick original finding to point to shadow file for pov
        finding_shadow = dict(finding)
        finding_shadow["file"] = shadow_file
        pov_result = pov_replay(patch_result, finding_shadow)
        local_item["pov"] = pov_result
        _pov_status = pov_result["status"]
        _pov_detail = pov_result['detail']
        if _pov_status == "PASS":
            local_logs.append(lambda d=_pov_detail: _ok(f"PROVE PoV:   {d}"))
        elif _pov_status == "FAIL":
            local_logs.append(lambda d=_pov_detail: _err(f"PROVE PoV:   {d}"))
        else:
            local_logs.append(lambda d=_pov_detail: _warn(f"PROVE PoV:   {d}"))

        # PROVE - Differential replay
        diff_result = run_differential(
            original_file=finding.get("file", ""),
            patched_file=shadow_file,
            backup_path=finding.get("file", ""), # Live file is untouched
            cwe_class=cwe,
        )
        local_item["differential"] = diff_result
        
        def _diff_log(dr=diff_result):
            marker = _ok if dr["status"] == "PASS" else (_warn if dr["status"] == "PARTIAL" else _err)
            marker(f"PROVE Diff:  {dr['summary']}")
        local_logs.append(_diff_log)

        # PROVE - Regression check
        reg_result = run_regression(target_path, patch_result)
        local_item["regression"] = reg_result
        _reg_status = reg_result["status"]
        _reg_detail = reg_result['detail'][:100]
        if _reg_status == "NO_SUITE_PRESENT":
            local_logs.append(lambda d=_reg_detail: _warn(f"PROVE Reg:   {d}"))
        elif _reg_status == "PASS":
            local_logs.append(lambda d=_reg_detail: _ok(f"PROVE Reg:   {d}"))
        else:
            local_logs.append(lambda d=_reg_detail: _err(f"PROVE Reg:   {d}"))

        # PROVE - Post-patch Fuzzing
        post_fuzz_target = str(Path(shadow_file).parent) if Path(shadow_file).is_file() else shadow_file
        post_fuzz_findings = run_atheris_fuzzer(post_fuzz_target, {finding.get("enclosing_function")} if finding.get("enclosing_function") else set())
        if post_fuzz_findings is None:
            post_fuzz_result = {"status": "SKIPPED", "detail": "Fuzzer not installed."}
            local_logs.append(lambda d=post_fuzz_result['detail']: _warn(f"PROVE Fuzz:  {d}"))
        elif len(post_fuzz_findings) == 0:
            post_fuzz_result = {"status": "PASS", "detail": "Post-patch fuzzing found 0 crashes."}
            local_logs.append(lambda d=post_fuzz_result['detail']: _ok(f"PROVE Fuzz:  {d}"))
        else:
            post_fuzz_result = {"status": "FAIL", "detail": f"Fuzzer found {len(post_fuzz_findings)} crashes post-patch!"}
            local_logs.append(lambda d=post_fuzz_result['detail']: _err(f"PROVE Fuzz:  {d}"))
        local_item["post_fuzz"] = post_fuzz_result

        # GATE - Confidence scoring
        gate_result = gate_score(pov_result, diff_result, reg_result, patch_result, post_fuzz_result)
        local_item["gate"] = gate_result
        decision = gate_result["decision"]
        score_val = gate_result["score"]
        
        if decision == "AUTO_MERGE":
            swap_shadow(patch_result)
            local_logs.append(lambda sv=score_val: _ok(f"GATE:  score={sv:.2f}  -> AUTO_MERGE v"))
        elif decision == "HUMAN_REVIEW":
            cleanup_shadow(patch_result)
            local_logs.append(lambda sv=score_val: _warn(f"GATE:  score={sv:.2f}  -> HUMAN_REVIEW /!\\  (evidence bundle attached in report)"))
        else:
            cleanup_shadow(patch_result)
            local_logs.append(lambda sv=score_val: _err(f"GATE:  score={sv:.2f}  -> REJECT x"))


    def process_file_group(file_group):
        # We process findings in the same file sequentially (bottom-up) to avoid AST offset corruption
        results = []
        for finding in file_group:
            results.append(process_finding(finding))
        return results

    # Group by file
    findings_by_file = []
    survivors_by_file = sorted(survivors_ordered, key=lambda f: f.get("file", ""))
    for k, g in groupby(survivors_by_file, key=lambda f: f.get("file", "")):
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
                        
                        if local_item.get("patch_spec", {}).get("llm_generated"):
                            ledger_append(f"CLOUD_FALLBACK_USED", {"finding_id": fid})
                            
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


    # - PHASE 8: REPORT ------------------------------------------------------
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
        _ok(f"Ledger chain verified - {msg}")
    else:
        _err(f"Ledger chain BROKEN - {msg}")

    print()


def cmd_verify(ledger_path: str, pubkey_path: str) -> None:
    """Standalone ledger chain verification - no pipeline run needed."""
    from ledger.ledger import verify_chain
    led = Path(ledger_path)
    pub = Path(pubkey_path)
    if not led.exists():
        print(f"Error: ledger file not found: {led}")
        sys.exit(1)
    if not pub.exists():
        print(f"Error: public key file not found: {pub}")
        sys.exit(1)
    print(f"\nVerifying ledger : {led}")
    print(f"Public key       : {pub}")
    print("-" * 60)
    ok, msg = verify_chain(ledger_path=str(led), pubkey_path=str(pub))
    if ok:
        print(f"  [OK] Chain VALID  - {msg}")
    else:
        print(f"  [!!] Chain BROKEN - {msg}")
        sys.exit(1)
    print()



def cmd_approve(finding_id: str, operator_id: str) -> None:
    from ledger.ledger import append as ledger_append, load as ledger_load
    chain = ledger_load()
    # Check if finding is currently in HUMAN_REVIEW
    for entry in reversed(chain):
        if entry.get("stage") == f"FINDING_{finding_id}":
            if entry["data"].get("gate_decision") == "HUMAN_REVIEW":
                ledger_append("COMMANDER_APPROVAL", {"finding_id": finding_id, "operator_id": operator_id})
                print(f"  [OK] Finding {finding_id} explicitly APPROVED by {operator_id}.")
                return
            else:
                print(f"  [!!] Finding {finding_id} cannot be approved (state is {entry['data'].get('gate_decision')}).")
                return
    print(f"  [!!] Finding {finding_id} not found in ledger.")

def cmd_reject(finding_id: str, operator_id: str) -> None:
    from ledger.ledger import append as ledger_append, load as ledger_load
    chain = ledger_load()
    # Check if finding is currently in HUMAN_REVIEW
    for entry in reversed(chain):
        if entry.get("stage") == f"FINDING_{finding_id}":
            if entry["data"].get("gate_decision") == "HUMAN_REVIEW":
                ledger_append("COMMANDER_REJECTION", {"finding_id": finding_id, "operator_id": operator_id})
                print(f"  [OK] Finding {finding_id} explicitly REJECTED by {operator_id}.")
                return
            else:
                print(f"  [!!] Finding {finding_id} cannot be rejected (state is {entry['data'].get('gate_decision')}).")
                return
    print(f"  [!!] Finding {finding_id} not found in ledger.")

def cmd_export_ledger(output_zip: str) -> None:
    import zipfile
    from pathlib import Path
    import os
    if not output_zip.endswith(".zip"):
        output_zip += ".zip"
    
    with zipfile.ZipFile(output_zip, 'w') as zf:
        if Path("run_output/ledger.json").exists():
            zf.write("run_output/ledger.json", "ledger.json")
        if Path("run_output/ledger_pub.pem").exists():
            zf.write("run_output/ledger_pub.pem", "ledger_pub.pem")
    print(f"  [OK] Ledger exported to {output_zip} for Convoy transport.")

def cmd_merge_ledger(input_zip: str) -> None:
    import zipfile
    from pathlib import Path
    import tempfile
    import shutil
    from ledger.ledger import verify_chain, append as ledger_append, load as ledger_load
    
    if not Path(input_zip).exists():
        print(f"  [!!] Zip file {input_zip} not found.")
        return
        
    with tempfile.TemporaryDirectory() as td:
        with zipfile.ZipFile(input_zip, 'r') as zf:
            zf.extractall(td)
        
        led_path = Path(td) / "ledger.json"
        pub_path = Path(td) / "ledger_pub.pem"
        
        if not led_path.exists() or not pub_path.exists():
            print("  [!!] Invalid ledger bundle (missing json or pubkey).")
            return
            
        ok, msg = verify_chain(str(led_path), str(pub_path))
        if not ok:
            print(f"  [!!] Incoming ledger chain is broken. Refusing to merge. ({msg})")
            return
            
        # Append incoming entries to local ledger
        # We don't just copy the file, we append them one by one to cryptographically seal them under OUR key
        import json
        incoming = json.loads(led_path.read_text())
        print(f"  [OK] Incoming ledger verified ({len(incoming)} entries). Merging...")
        for entry in incoming:
            # Re-sign the incoming data payload using our local key
            ledger_append(entry.get("stage"), entry["data"])
        
        print("  [OK] Merge complete.")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Kavach-CRS CLI")
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    
    run_p = subparsers.add_parser("run", help="Run full pipeline")
    run_p.add_argument("target_path", help="Path to target directory")
    run_p.add_argument("--allow-cloud-fallback", action="store_true", help="Allow LLM to run in cloud")
    run_p.add_argument("--no-sovereign-mode", action="store_true", help="Disable sovereign network blocking")
    
    ver_p = subparsers.add_parser("verify", help="Verify ledger chain")
    ver_p.add_argument("ledger_json")
    ver_p.add_argument("ledger_pub")
    
    app_p = subparsers.add_parser("approve", help="Approve a HUMAN_REVIEW patch")
    app_p.add_argument("finding_id")
    app_p.add_argument("operator_id")
    
    rej_p = subparsers.add_parser("reject", help="Reject a HUMAN_REVIEW patch")
    rej_p.add_argument("finding_id")
    rej_p.add_argument("operator_id")
    
    exp_p = subparsers.add_parser("export-ledger", help="Export ledger to a zip bundle (Convoy Mode)")
    exp_p.add_argument("output_zip")
    
    mer_p = subparsers.add_parser("merge-ledger", help="Merge an external ledger bundle (Convoy Mode)")
    mer_p.add_argument("input_zip")
    
    args = parser.parse_args()
    
    if args.cmd == "verify":
        cmd_verify(args.ledger_json, args.ledger_pub)
    elif args.cmd == "run":
        target = Path(args.target_path).resolve()
        crs_root = Path(__file__).parent.resolve()
        if not target.exists() or target == crs_root or target in crs_root.parents:
            print("Error: Invalid target path.")
            sys.exit(1)
        run(str(target), args.allow_cloud_fallback)
    elif args.cmd == "approve":
        cmd_approve(args.finding_id, args.operator_id)
    elif args.cmd == "reject":
        cmd_reject(args.finding_id, args.operator_id)
    elif args.cmd == "export-ledger":
        cmd_export_ledger(args.output_zip)
    elif args.cmd == "merge-ledger":
        cmd_merge_ledger(args.input_zip)


if __name__ == "__main__":
    main()

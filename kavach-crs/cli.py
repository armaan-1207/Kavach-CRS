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
    findings = run_detection(target_path)
    print(f"  Bandit + custom AST rules: {len(findings)} raw findings")
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

    for finding in survivors_ordered:
        fid = finding.get("id", "?")
        cwe = finding.get("cwe", "")
        _sep(f"{fid}  {cwe}")
        _info(f"{Path(finding.get('file','')).name}:{finding.get('line','')}  "
              f"[{finding.get('severity','')}]  fn:{finding.get('enclosing_function','?')}  "
              f"tier:{finding.get('mission_tier','?')}")
        _info(finding.get("snippet", "")[:100])

        item: dict = {"finding": finding}

        # REASON
        patch_spec = reason_all([finding])[0]
        item["patch_spec"] = patch_spec
        if patch_spec.get("status") == "TEMPLATE_MISS":
            _warn(f"REASON: template miss — {patch_spec.get('rationale','')}")
        else:
            _ok(f"REASON: patch generated for {cwe}")

        # PATCH
        patch_result = apply_patch(patch_spec)
        item["patch"] = patch_result
        if patch_result["status"] == "PATCHED":
            counts["patched"] += 1
            _ok(f"PATCH:  applied  ({len(patch_result['unified_diff'].splitlines())} diff lines)"
                f"  backup→ {Path(patch_result['backup_path']).name}")
        elif patch_result["status"] == "SKIPPED":
            counts["skipped"] += 1
            _warn(f"PATCH:  skipped — {patch_result['reason']}")
        else:
            _err(f"PATCH:  error — {patch_result['reason']}")

        # PROVE — PoV replay
        pov_result = pov_replay(patch_result, finding)
        item["pov"] = pov_result
        if pov_result["status"] == "PASS":
            counts["pov_pass"] += 1
            _ok(f"PROVE PoV:   {pov_result['detail']}")
        elif pov_result["status"] == "FAIL":
            _err(f"PROVE PoV:   {pov_result['detail']}")
        else:
            _warn(f"PROVE PoV:   {pov_result['detail']}")

        # PROVE — Differential replay
        diff_result = run_differential(
            original_file=finding.get("file", ""),
            patched_file=finding.get("file", ""),
            backup_path=patch_result.get("backup_path", ""),
            cwe_class=cwe,
        )
        item["differential"] = diff_result
        marker = _ok if diff_result["status"] == "PASS" else (_warn if diff_result["status"] == "PARTIAL" else _err)
        marker(f"PROVE Diff:  {diff_result['summary']}")

        # PROVE — Regression check
        reg_result = run_regression(target_path, patch_result)
        item["regression"] = reg_result
        if reg_result["status"] == "NO_SUITE_PRESENT":
            _warn(f"PROVE Reg:   {reg_result['detail'][:100]}")
        elif reg_result["status"] == "PASS":
            _ok(f"PROVE Reg:   {reg_result['detail']}")
        else:
            _err(f"PROVE Reg:   {reg_result['detail'][:100]}")

        # GATE — Confidence scoring
        gate_result = gate_score(pov_result, diff_result, reg_result, patch_result)
        item["gate"] = gate_result
        decision = gate_result["decision"]
        score_val = gate_result["score"]
        if decision == "AUTO_MERGE":
            counts["auto_merge"] += 1
            _ok(f"GATE:  score={score_val:.2f}  → AUTO_MERGE ✓")
        elif decision == "HUMAN_REVIEW":
            counts["human_review"] += 1
            _warn(f"GATE:  score={score_val:.2f}  → HUMAN_REVIEW ⚠  (evidence bundle attached in report)")
        else:
            counts["reject"] += 1
            _err(f"GATE:  score={score_val:.2f}  → REJECT ✗")

        # Ledger entry for this finding
        ledger_append(f"FINDING_{fid}", {
            "finding_id": fid,
            "cwe": cwe,
            "patch_status": patch_result.get("status"),
            "pov": pov_result.get("status"),
            "diff_replay": diff_result.get("status"),
            "regression": reg_result.get("status"),
            "gate_score": score_val,
            "gate_decision": decision,
        })

        run_summary["items"].append(item)

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

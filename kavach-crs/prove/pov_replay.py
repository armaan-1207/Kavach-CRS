"""
PoV Replay — Kavach-CRS Phase 6 (PROVE step 1)

Re-runs the DETECT stage on the patched file and confirms that the specific
finding that was patched is no longer present.

"The specific finding must be gone" — if it's still there, the patch failed.
"""
from detect.sast import run_detection


def pov_replay(patch_result: dict, original_finding: dict) -> dict:
    """
    Returns a prove result dict:
    {
        "status":   "PASS" | "FAIL" | "SKIPPED"
        "finding_id": str
        "detail":   str
    }
    """
    finding_id = original_finding.get("id", "?")

    if patch_result.get("status") != "PATCHED":
        return {
            "status": "SKIPPED",
            "finding_id": finding_id,
            "detail": f"Patch was {patch_result.get('status')} — PoV replay skipped.",
        }

    filepath = patch_result["file"]
    new_findings = run_detection(filepath)

    # Scope check to the same file only — don't let findings in other files
    # (e.g. dead_code.py) mask a successful fix in the patched file.
    import os as _os
    same_file_findings = [
        f for f in new_findings
        if _os.path.abspath(f.get("file", "")) == _os.path.abspath(filepath)
    ]

    # Match by rule (most specific), then fall back to CWE + line proximity.
    original_cwe = original_finding.get("cwe", "")
    original_rule = original_finding.get("rule", "")
    original_line = original_finding.get("line", -1)

    def _is_same_finding(f: dict) -> bool:
        # Exact rule match — e.g. B602 != B603 even though both are CWE-78
        if original_rule and f.get("rule"):
            if f.get("rule") == original_rule:
                return abs(f["line"] - original_line) <= 5
            return False
        # Fall back: same CWE and close line (for custom-ast findings)
        return f["cwe"] == original_cwe and abs(f["line"] - original_line) <= 2

    still_present = any(_is_same_finding(f) for f in same_file_findings)

    if still_present:
        return {
            "status": "FAIL",
            "finding_id": finding_id,
            "detail": (
                f"PoV FAIL: {original_cwe} still detected near line {original_line} "
                f"in patched file. Patch did not eliminate the vulnerability."
            ),
        }

    return {
        "status": "PASS",
        "finding_id": finding_id,
        "detail": (
            f"PoV PASS: {original_cwe} no longer detected in patched file. "
            f"Original finding at line {original_line} is gone."
        ),
    }

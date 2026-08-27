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

    # Check if the original finding's (line, cwe) is still present
    original_cwe = original_finding.get("cwe", "")
    original_line = original_finding.get("line", -1)

    # Allow ±2 line tolerance (patch may shift line numbers)
    still_present = any(
        f["cwe"] == original_cwe and abs(f["line"] - original_line) <= 2
        for f in new_findings
    )

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

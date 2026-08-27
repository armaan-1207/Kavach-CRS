"""
REASON engine — Kavach-CRS Phase 4

Routes each triaged finding to the correct CWE template and returns a
PatchSpec with rationale.  If no template matches, returns a stub PatchSpec
clearly marked as TEMPLATE_MISS so it shows up honestly in the ledger.
"""
from pathlib import Path
from typing import Optional

from reason.templates import (
    patch_sqli,
    patch_cmdinj,
    patch_path_traversal,
    patch_hardcoded_cred,
)

# Map CWE → template function
_TEMPLATE_REGISTRY = {
    "CWE-89":  patch_sqli,
    "CWE-78":  patch_cmdinj,
    "CWE-22":  patch_path_traversal,
    "CWE-798": patch_hardcoded_cred,
}


def reason(finding: dict) -> dict:
    """
    Given a triaged finding dict, return a PatchSpec.

    Always returns a dict — never raises.  If reasoning fails, the returned
    spec has status="TEMPLATE_MISS" so downstream stages can handle gracefully
    and the ledger shows it honestly.
    """
    cwe = finding.get("cwe", "")
    filepath = finding.get("file", "")

    try:
        source_lines = Path(filepath).read_text(encoding="utf-8").splitlines(keepends=True)
    except (FileNotFoundError, OSError) as e:
        return _miss(finding, reason=f"Could not read source file: {e}")

    # Try exact CWE match
    template_fn = _TEMPLATE_REGISTRY.get(cwe)
    if template_fn is None:
        # Try prefix match (e.g. "CWE-78" from "CWE-78 (B602)")
        for key, fn in _TEMPLATE_REGISTRY.items():
            if cwe.startswith(key):
                template_fn = fn
                break

    if template_fn is None:
        return _miss(finding, reason=f"No template for {cwe} — LLM fallback not enabled in this build.")

    patch_spec = template_fn(source_lines, finding)
    if patch_spec is None:
        return _miss(finding, reason=f"Template for {cwe} could not parse line {finding.get('line')}.")

    patch_spec["status"] = "REASONED"
    patch_spec["finding_id"] = finding.get("id", "?")
    patch_spec["file"] = filepath
    return patch_spec


def _miss(finding: dict, reason: str) -> dict:
    return {
        "status": "TEMPLATE_MISS",
        "finding_id": finding.get("id", "?"),
        "file": finding.get("file", ""),
        "line_number": finding.get("line", 0),
        "cwe": finding.get("cwe", ""),
        "rationale": f"[STUB] {reason}",
        "old_lines": [],
        "new_lines": [],
    }


def reason_all(findings: list[dict]) -> list[dict]:
    """Run reason() on every finding and return the list of PatchSpecs."""
    return [reason(f) for f in findings]

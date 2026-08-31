"""
DETECT stage - Kavach-CRS

Runs Bandit (as subprocess) + custom AST rules, then normalises all findings
into a single list of dicts:

    {
        "id":         str   - unique finding ID, e.g. "F001"
        "file":       str   - absolute path
        "line":       int
        "cwe":        str   - e.g. "CWE-89"
        "rule":       str   - bandit test ID or custom rule name
        "severity":   str   - HIGH / MEDIUM / LOW
        "confidence": str   - HIGH / MEDIUM / LOW
        "snippet":    str   - the offending source line
        "source":     str   - "bandit" | "custom-ast"
    }
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from detect.rules import run_custom_rules

# Map Bandit test IDs to CWE numbers for the most common findings
_BANDIT_CWE_MAP = {
    "B105": "CWE-798",   # hardcoded password
    "B106": "CWE-798",   # hardcoded password (funcarg)
    "B107": "CWE-798",   # hardcoded password (default)
    "B108": "CWE-377",   # probable insecure temp file
    "B201": "CWE-94",    # flask debug=True
    "B202": "CWE-22",    # tarfile unsafe extraction
    "B301": "CWE-502",   # pickle
    "B302": "CWE-502",   # marshal.loads
    "B303": "CWE-327",   # MD5/SHA1
    "B304": "CWE-327",   # ciphers
    "B305": "CWE-327",   # cipher modes
    "B306": "CWE-377",   # mktemp
    "B307": "CWE-78",    # eval
    "B310": "CWE-918",   # urllib (SSRF)
    "B311": "CWE-330",   # random
    "B312": "CWE-605",   # telnet
    "B313": "CWE-611",   # xml
    "B320": "CWE-611",   # xml etree
    "B324": "CWE-327",   # hashlib insecure
    "B401": "CWE-319",   # import telnetlib
    "B403": "CWE-502",   # import pickle
    "B404": "CWE-78",    # import subprocess
    "B501": "CWE-295",   # ssl verify=False
    "B506": "CWE-20",    # yaml.load
    "B601": "CWE-78",    # paramiko exec
    "B602": "CWE-78",    # subprocess shell=True
    "B603": "CWE-78",    # subprocess no shell
    "B604": "CWE-78",    # any shell=True
    "B605": "CWE-78",    # start_process_with_a_shell
    "B606": "CWE-78",    # start_process_no_shell
    "B607": "CWE-78",    # start_process_partial_path
    "B608": "CWE-89",    # hardcoded_sql_expressions
    "B609": "CWE-78",    # linux_commands_wildcard_injection
}


def _run_bandit(target_path: str) -> list[dict]:
    """Run Bandit on target_path and return normalised findings."""
    cmd = [
        sys.executable, "-m", "bandit",
        "-r", target_path,
        "-x", "venv,env,.venv,.env,node_modules,.git",
        "-f", "json",
        "-q",
        "--severity-level", "low",
        "--confidence-level", "low",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return []
    try:
        # Try to parse even if returncode != 0 (Bandit might dump partial JSON + error)
        start = result.stdout.find("{")
        if start >= 0:
            data = json.loads(result.stdout[start:])
        else:
            data = {"results": []}
    except json.JSONDecodeError:
        return []

    from detect.rules import _mask_secret
    findings = []
    for issue in data.get("results", []):
        test_id = issue.get("test_id", "")
        cwe = _BANDIT_CWE_MAP.get(test_id, f"CWE-UNKNOWN({test_id})")
        snippet = (issue.get("code", "").strip().splitlines() or [""])[0] if issue.get("code") else ""
        
        if cwe == "CWE-798":
            snippet = _mask_secret(snippet)
            
        findings.append({
            "file": issue["filename"],
            "line": issue["line_number"],
            "cwe": cwe,
            "rule": test_id,
            "severity": issue.get("issue_severity", "MEDIUM").upper(),
            "confidence": issue.get("issue_confidence", "MEDIUM").upper(),
            "snippet": snippet,
            "source": "bandit"
        })
    return findings


def _run_custom(target_path: str) -> list[dict]:
    """Run custom AST rules across all .py files in target_path."""
    findings = []
    root = Path(target_path)
    py_files = []
    
    if root.is_dir():
        for path in root.rglob("*.py"):
            # Exclude virtual environments and package directories
            if any(p in ("venv", "env", ".venv", ".env", "node_modules", ".git") for p in path.parts):
                continue
            py_files.append(path)
            if len(py_files) >= 5000:
                break
    else:
        py_files = [root]

    for f in py_files:
        for finding in run_custom_rules(str(f)):
            finding.setdefault("severity", "HIGH")
            finding.setdefault("source", "custom-ast")
            findings.append(finding)
    return findings


def _filter_noise(findings: list[dict]) -> list[dict]:
    """
    Remove low-signal import-level Bandit findings that flag bare import
    statements rather than actual vulnerable code patterns.
    These produce misleading TEMPLATE_MISS entries and no real patch target.
    """
    # These rules only fire on `import X` lines - not actual vuln patterns
    _IMPORT_ONLY_RULES = {"B401", "B402", "B403", "B404", "B405", "B406",
                          "B407", "B408", "B409", "B410", "B411", "B412"}
    # B607 and B603 often flag secure patterns, but we shouldn't drop them entirely
    # as they might be true positives on other codebases. Downgrade to LOW.
    _SECURE_PATTERN_NOISE = {"B603", "B607"}
    
    kept = []
    for f in findings:
        rule = f.get("rule", "")
        # Bug fix: don't silently drop B401-B412, downgrade them to LOW
        if rule in _IMPORT_ONLY_RULES:
            f["severity"] = "LOW"
            f["confidence"] = "LOW"
            kept.append(f)
        elif rule in _SECURE_PATTERN_NOISE:
            f["severity"] = "LOW"
            f["confidence"] = "LOW"
            kept.append(f)
        else:
            kept.append(f)
    return kept


def _deduplicate(findings: list[dict]) -> list[dict]:
    """Remove exact duplicates (same file + line + cwe) keeping highest confidence."""
    seen: dict[tuple, dict] = {}
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for f in findings:
        key = (f["file"], f["line"], f["cwe"])
        if key not in seen or order.get(f["confidence"], 0) > order.get(seen[key]["confidence"], 0):
            seen[key] = f
    return list(seen.values())


def run_detection(target_path: str) -> list[dict]:
    """
    Main entry point for DETECT stage.
    Returns a deduplicated, ID-tagged list of normalised findings.
    """
    target_abs = str(Path(target_path).resolve())
    bandit_findings = _run_bandit(target_abs)
    custom_findings = _run_custom(target_abs)

    all_findings = _deduplicate(_filter_noise(bandit_findings) + custom_findings)

    # Sort: severity HIGH first, then MEDIUM, then LOW
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_findings.sort(key=lambda f: (sev_order.get(f["severity"], 3), f["file"], f["line"]))

    # Assign stable IDs
    for i, f in enumerate(all_findings, start=1):
        f["id"] = f"F{i:03d}"

    return all_findings


if __name__ == "__main__":
    import sys, pprint
    findings = run_detection(sys.argv[1] if len(sys.argv) > 1 else "target_app/")
    pprint.pprint(findings)
    print(f"\nTotal findings: {len(findings)}")

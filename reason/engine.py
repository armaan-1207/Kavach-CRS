"""
REASON engine — Kavach-CRS Phase 4

Routes each triaged finding to the correct CWE template and returns a
PatchSpec with rationale.  If no template matches, returns a stub PatchSpec
clearly marked as TEMPLATE_MISS so it shows up honestly in the ledger.
"""
import os
import json
from pathlib import Path
from typing import Optional

from reason.templates import (
    patch_sqli,
    patch_cmdinj,
    patch_path_traversal,
    patch_hardcoded_cred,
    patch_flask_debug,
    patch_insecure_deserialization,
    patch_ssti,
)

# Map CWE to template function (primary)
_TEMPLATE_REGISTRY = {
    "CWE-89":  patch_sqli,
    "CWE-78":  patch_cmdinj,
    "CWE-22":  patch_path_traversal,
    "CWE-798": patch_hardcoded_cred,
    "CWE-94":  patch_flask_debug,
    "CWE-502": patch_insecure_deserialization,
}

# Secondary registry: engine tries primary first, then these fallbacks.
_TEMPLATE_SECONDARY = {
    "CWE-94": patch_ssti,  # SSTI via render_template_string vs debug=True
}


def reason(finding: dict, allow_cloud_fallback: bool = False) -> dict:
    cwe = finding.get("cwe", "")
    filepath = finding.get("file", "")

    try:
        source_lines = Path(filepath).read_text(encoding="utf-8-sig").splitlines(keepends=True)
    except (FileNotFoundError, OSError) as e:
        return _miss(finding, reason=f"Could not read source file: {e}")

    template_fn = _TEMPLATE_REGISTRY.get(cwe)
    if template_fn is None:
        for key, fn in _TEMPLATE_REGISTRY.items():
            if cwe.startswith(key):
                template_fn = fn
                break

    if template_fn is None:
        llm_spec = _llm_fallback(source_lines, finding, allow_cloud_fallback)
        if llm_spec:
            llm_spec["finding_id"] = finding.get("id", "?")
            llm_spec["file"] = filepath
            return llm_spec
        return _miss(finding, reason=f"No template for {cwe} and LLM fallback failed or LLM not configured.")

    patch_spec = template_fn(source_lines, finding)
    if patch_spec is None:
        secondary_fn = _TEMPLATE_SECONDARY.get(cwe)
        if secondary_fn:
            patch_spec = secondary_fn(source_lines, finding)

    if patch_spec is None:
        llm_spec = _llm_fallback(source_lines, finding, allow_cloud_fallback)
        if llm_spec:
            llm_spec["finding_id"] = finding.get("id", "?")
            llm_spec["file"] = filepath
            return llm_spec
        line_no = finding.get("line")
        return _miss(finding, reason=f"Template for {cwe} could not parse line {line_no} and LLM fallback failed.")

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


def reason_all(findings: list[dict], allow_cloud_fallback: bool = False) -> list[dict]:
    return [reason(f, allow_cloud_fallback) for f in findings]


def _llm_fallback(source_lines: list[str], finding: dict, allow_cloud_fallback: bool) -> dict | None:
    provider = os.environ.get("KAVACH_LLM_PROVIDER", "gemini").lower()

    if provider == "gemini" and not allow_cloud_fallback:
        print("  [!!] Cloud fallback disabled (Sovereign Mode). Use --allow-cloud-fallback to enable.")
        return None

    cwe = finding.get("cwe", "vulnerability")

    mitigation_context = ""
    try:
        rag_path = Path(__file__).parent / "cwe_mitigations.json"
        if rag_path.exists():
            rag_data = json.loads(rag_path.read_text())
            if cwe in rag_data:
                miti = rag_data[cwe]
                mitigation_context = (
                    f"\nMITRE ATT&CK Mapping: {miti.get('mitre_attack')}"
                    f"\nRequired Mitigation Strategy: {miti.get('mitigation')}\n"
                )
    except Exception as e:
        print(f"Warning: Failed to load RAG context: {e}")

    lineno = finding.get("line", 1) - 1
    start = max(0, lineno - 10)
    end = min(len(source_lines), lineno + 11)
    snippet = "".join(source_lines[start:end])
    safe_snippet = snippet.replace("\\", "\\\\")

    combined_prompt = (
        f"You are an expert military cyber-defense engineer patching a {cwe} in Python.\n"
        f"Vulnerability is at line {lineno + 1}.\n"
        f"{mitigation_context}\n"
        f"Context:\n```python\n{safe_snippet}```\n\n"
        f"Analyze the vulnerability and return a valid JSON object matching this schema:\n"
        f"{{\n"
        f'  "rca": "A concise 1-2 sentence root cause analysis explaining why the vulnerability exists",\n'
        f'  "start_line": <int: starting line number to replace>,\n'
        f'  "end_line": <int: ending line number to replace (inclusive)>,\n'
        f'  "new_lines": [<str: replacement lines of code>]\n'
        f"}}\n"
        f"Do NOT include markdown formatting, backticks, or text before/after the JSON."
    )

    def call_llm(prompt_str):
        if provider == "local":
            base_url = os.environ.get("KAVACH_LOCAL_LLM_URL", "http://localhost:11434/v1")
            model_name = os.environ.get("KAVACH_LOCAL_MODEL", "qwen2.5-coder")
            import urllib.request
            req = urllib.request.Request(
                f"{base_url}/chat/completions",
                data=json.dumps({
                    "model": model_name,
                    "messages": [{"role": "user", "content": prompt_str}],
                    "temperature": 0,
                }).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=90) as response:
                result = json.loads(response.read())
                return result["choices"][0]["message"]["content"]
        else:
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                return None
            
            masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "INVALID_LENGTH"
            
            import urllib.request
            import urllib.error
            import time
            
            # Preemptive rate limiting: Free tier allows 15 RPM. 
            # Sleeping 4.5s guarantees max ~13 RPM, preventing 429 burst blocks.
            time.sleep(4.5)
            
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={api_key}"
            req = urllib.request.Request(
                url,
                data=json.dumps({
                    "contents": [{"parts": [{"text": prompt_str}]}],
                    "generationConfig": {"temperature": 0}
                }).encode(),
                headers={"Content-Type": "application/json"}
            )
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(req, timeout=90) as response:
                        result = json.loads(response.read())
                        return result["candidates"][0]["content"]["parts"][0]["text"]
                except urllib.error.HTTPError as e:
                    error_body = e.read().decode('utf-8', errors='ignore')
                    if e.code == 429:
                        print(f"  [DEBUG] Using API Key: {masked_key}")
                        print(f"  [DEBUG] 429 Rate Limit Hit! Google says: {error_body.strip()}")
                        print(f"  [DEBUG] Sleeping {(attempt + 1) * 3}s (attempt {attempt+1}/5)...")
                        time.sleep((attempt + 1) * 3)
                        continue
                    print(f"  [DEBUG] Using API Key: {masked_key}")
                    print(f"  [DEBUG] HTTPError {e.code}: {error_body}")
                    raise e
                except Exception as e:
                    print(f"  [DEBUG] Request failed: {e}")
                    raise e
            print("  [DEBUG] Exhausted all 5 retries for 429.")
            return None

    try:
        response = call_llm(combined_prompt)
        if not response:
            print("  [DEBUG] call_llm returned None (possibly 429 exhaustion or invalid API key)")
            return None

        import re
        clean_json = re.sub(r"^```(?:json)?\s*|\s*```$", "", response.strip(), flags=re.DOTALL)
        
        try:
            parsed = json.loads(clean_json)
        except json.JSONDecodeError as e:
            print(f"  [DEBUG] LLM JSON parsing failed: {e}\n  Response was:\n{response}")
            return None
        
        rca = parsed.get("rca", "Vulnerability detected in target application.")
        sl = parsed.get("start_line")
        el = parsed.get("end_line")

        if sl is None or el is None or not (1 <= sl <= el <= len(source_lines)):
            print(f"  [DEBUG] Invalid lines: sl={sl}, el={el}, total_lines={len(source_lines)}")
            return None

        return {
            "line_number": sl,
            "start_line": sl,
            "end_line": el,
            "old_lines": source_lines[sl - 1:el],
            "new_lines": parsed.get("new_lines", []),
            "rationale": f"[LLM GENERATED - {provider.upper()}] RCA: {rca[:100]}...",
            "llm_generated": True,
        }
    except Exception as e:
        import traceback
        print(f"  [DEBUG] LLM fallback exception: {e}")
        traceback.print_exc()
        return None

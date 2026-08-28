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
    patch_flask_debug,
)

# Map CWE → template function
_TEMPLATE_REGISTRY = {
    "CWE-89":  patch_sqli,
    "CWE-78":  patch_cmdinj,
    "CWE-22":  patch_path_traversal,
    "CWE-798": patch_hardcoded_cred,
    "CWE-94":  patch_flask_debug,
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
        llm_spec = _llm_fallback(source_lines, finding)
        if llm_spec:
            llm_spec["finding_id"] = finding.get("id", "?")
            llm_spec["file"] = filepath
            return llm_spec
        return _miss(finding, reason=f"No template for {cwe} and LLM fallback failed or GEMINI_API_KEY unset.")

    patch_spec = template_fn(source_lines, finding)
    if patch_spec is None:
        llm_spec = _llm_fallback(source_lines, finding)
        if llm_spec:
            llm_spec["finding_id"] = finding.get("id", "?")
            llm_spec["file"] = filepath
            return llm_spec
        return _miss(finding, reason=f"Template for {cwe} could not parse line {finding.get('line')} and LLM fallback failed.")

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
import os
import json

def _llm_fallback(source_lines: list[str], finding: dict) -> dict | None:
    provider = os.environ.get("KAVACH_LLM_PROVIDER", "gemini").lower()
    cwe = finding.get('cwe', 'vulnerability')
    
    # Offline RAG Context Injection
    mitigation_context = ""
    try:
        import json
        from pathlib import Path
        rag_path = Path(__file__).parent / "cwe_mitigations.json"
        if rag_path.exists():
            rag_data = json.loads(rag_path.read_text())
            if cwe in rag_data:
                miti = rag_data[cwe]
                mitigation_context = f"\nMITRE ATT&CK Mapping: {miti.get('mitre_attack')}\nRequired Mitigation Strategy: {miti.get('mitigation')}\n"
    except Exception as e:
        print(f"Warning: Failed to load RAG context: {e}")

    lineno = finding.get("line", 1) - 1
    start = max(0, lineno - 10)
    end = min(len(source_lines), lineno + 11)
    snippet = "".join(source_lines[start:end])
    
    prompt = f"""
You are an expert military cyber-defense engineer patching a {cwe} in Python code.
The vulnerability is at line {lineno + 1}.
{mitigation_context}
Context:
```python
{snippet}
```
Return ONLY a valid JSON object matching this schema:
{{
  "start_line": <int>,
  "end_line": <int>,
  "new_lines": [<str>]
}}
Do NOT include markdown formatting or reasoning.
"""

    if provider == "local":
        # We recommend Qwen2.5-Coder or Codestral via Ollama for massive speed/accuracy gains over generic Llama3
        base_url = os.environ.get("KAVACH_LOCAL_LLM_URL", "http://localhost:11434/v1")
        model_name = os.environ.get("KAVACH_LOCAL_MODEL", "qwen2.5-coder")
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{base_url}/chat/completions",
                data=json.dumps({
                    "model": model_name,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0
                }).encode(),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                result = json.loads(response.read())
                raw = result["choices"][0]["message"]["content"]
                parsed = json.loads(raw.strip("` \n").removeprefix("json"))
                return {
                    "start_line": parsed["start_line"],
                    "end_line": parsed["end_line"],
                    "new_lines": parsed["new_lines"],
                    "rationale": f"[LLM GENERATED - {model_name.upper()}] Addressed {cwe}"
                }
        except Exception as e:
            print(f"Local LLM fallback ({model_name}) failed: {e}")
            return None
            
    # Default to Gemini (online convenience)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
        
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        
        lineno = finding.get("line", 1) - 1
        # Grab a context window around the vulnerable line
        start = max(0, lineno - 10)
        end = min(len(source_lines), lineno + 11)
        snippet = "".join(source_lines[start:end])
        
        prompt = f"""
You are an expert security engineer patching a {finding.get('cwe', 'vulnerability')} in Python code.
The vulnerability is at line {lineno + 1}.

Context:
`python
{snippet}
`

Write a patch for this vulnerability. Return ONLY a valid JSON object with the exact format:
{{
    "old_lines": ["<exact old line 1>", "<exact old line 2>"],
    "new_lines": ["<patched line 1>", "<patched line 2>"],
    "rationale": "Why this fixes the issue safely."
}}
Return NOTHING else. Do not wrap in markdown blocks, just raw JSON.
"""
        
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        
        resp_text = response.text.strip()
        if resp_text.startswith("`json"):
            resp_text = resp_text[7:-3]
            
        result = json.loads(resp_text)
        
        if not result.get("old_lines") or not result.get("new_lines"):
            return None
            
        # Verify the old_lines actually exist in the source exactly
        for i, old_line in enumerate(result["old_lines"]):
            if old_line not in "".join(source_lines):
                return None
                
        return {
            "rationale": f"[LLM GENERATED] {result.get('rationale', 'Generated by LLM fallback')}",
            "old_lines": result["old_lines"],
            "new_lines": result["new_lines"],
            "line_number": finding.get("line"),
            "cwe": finding.get("cwe"),
            "status": "REASONED_BY_LLM"
        }
    except Exception as e:
        print(f"LLM fallback failed: {e}")
        return None

"""
Patch synthesis templates — Kavach-CRS Phase 4 (REASON)

Deterministic CWE-keyed templates that produce minimal, behaviour-preserving
fixes scoped to the implicated line(s) only.  The LLM is never the sole
decision-maker; templates carry the demo load.

Each template function receives the source lines (list[str]) and the finding
dict, and returns a PatchSpec:
    {
        "rationale":      str   — human-readable explanation
        "old_lines":      list[str]  — lines to replace (exact match)
        "new_lines":      list[str]  — replacement lines
        "line_number":    int   — 1-indexed line of the vulnerability
    }
Returns None if the template cannot handle the finding.
"""
import re
from typing import Optional


PatchSpec = dict  # typed alias for clarity


# ── CWE-89: SQL Injection ────────────────────────────────────────────────────

def patch_sqli(lines: list[str], finding: dict) -> Optional[PatchSpec]:
    """
    Replace f-string / %-format SQL query with a parameterised query.
    Detects: f"... '{var}' ..." or "... '%s' ..." % var patterns.
    """
    lineno = finding["line"] - 1  # 0-indexed
    line = lines[lineno]

    # Pattern: query = f"... WHERE ... = '{something}'"
    fstring_re = re.compile(r"(query\s*=\s*)f(['\"])(.*?)\2", re.DOTALL)
    m = fstring_re.search(line)
    if m:
        raw_sql = m.group(3)
        # Replace '{var}' or "{var}" or bare {var} with bare ?
        # Must strip surrounding quote chars too, or SQL gets literal '?'
        param_sql, n_replacements = re.subn(r"""['"]\{[^}]+\}['"]|\{[^}]+\}""", "?", raw_sql)
        if n_replacements == 0:
            return None
        indent = len(line) - len(line.lstrip())
        prefix = " " * indent
        # Extract variable names in order
        var_names = re.findall(r"\{([^}]+)\}", m.group(3))
        params_tuple = f"({', '.join(var_names)},)" if len(var_names) == 1 else f"({', '.join(var_names)})"

        new_lines = [
            f"{prefix}# KAVACH-PATCH: parameterised query (CWE-89 fix)\n",
            f'{prefix}query = "{param_sql}"\n',
            f"{prefix}cur = conn.execute(query, {params_tuple})\n",
        ]
        # Find and remove the execute line immediately following if it exists
        old_exec_line = ""
        if lineno + 1 < len(lines) and "conn.execute(query)" in lines[lineno + 1]:
            old_exec_line = lines[lineno + 1]

        old_lines = [line]
        if old_exec_line:
            old_lines.append(old_exec_line)

        return {
            "rationale": (
                "Replaced f-string SQL interpolation with a parameterised query using "
                "sqlite3's ? placeholder. User-supplied values are now passed as a "
                "separate tuple, preventing SQL injection (CWE-89)."
            ),
            "old_lines": old_lines,
            "new_lines": new_lines,
            "line_number": finding["line"],
            "cwe": "CWE-89",
        }

    return None


# ── CWE-78: Command Injection ─────────────────────────────────────────────────

def patch_cmdinj(lines: list[str], finding: dict) -> Optional[PatchSpec]:
    """
    Replace shell=True subprocess call with a list-based invocation.
    Detects: subprocess.check_output(f"... {var}", shell=True, ...)
    """
    lineno = finding["line"] - 1
    line = lines[lineno]

    # Detect shell=True
    if "shell=True" not in line:
        return None

    indent = len(line) - len(line.lstrip())
    prefix = " " * indent

    # Try to extract the command template and user variables
    # Pattern: f"cmd {var}" or "cmd " + var
    fstr_re = re.compile(r'f["\']([^"\']+)["\']')
    m = fstr_re.search(line)
    if m:
        template = m.group(1)
        # Split into static parts and {var} placeholders
        # Build a list: ["static_word", variable, "static_word", ...]
        parts = re.split(r"(\{[^}]+\})", template)
        list_parts = []
        for part in parts:
            if part.startswith("{") and part.endswith("}"):
                list_parts.append(part[1:-1])  # variable name
            elif part.strip():
                # Split static parts by whitespace into individual tokens
                for token in part.split():
                    list_parts.append(f'"{token}"')
        cmd_list = "[" + ", ".join(list_parts) + "]"

        # Preserve the rest of the call (text=True etc.)
        # Extract kwargs after shell=True
        kwargs_match = re.search(r"shell=True,?\s*(.*?)\)", line)
        extra_kwargs = kwargs_match.group(1).strip() if kwargs_match else ""
        extra = f", {extra_kwargs}" if extra_kwargs else ""

        # Detect the function name: check_output / run / call
        func_re = re.search(r"subprocess\.(\w+)\(", line)
        func_name = func_re.group(1) if func_re else "check_output"

        # Detect the assignment target (left side of =)
        assign_re = re.search(r"^\s*(\w+)\s*=", line)
        lhs = assign_re.group(1) + " = " if assign_re else ""

        new_line = (
            f"{prefix}# KAVACH-PATCH: list-based subprocess, no shell (CWE-78 fix)\n"
            f"{prefix}{lhs}subprocess.{func_name}({cmd_list}{extra})\n"
        )
        return {
            "rationale": (
                "Replaced shell=True subprocess call with a list-based invocation. "
                "Shell metacharacters in user-supplied arguments are now inert because "
                "the OS receives them as literal argv elements, not a shell string (CWE-78)."
            ),
            "old_lines": [line],
            "new_lines": [new_line],
            "line_number": finding["line"],
            "cwe": "CWE-78",
        }

    return None


# ── CWE-22: Path Traversal ────────────────────────────────────────────────────

def patch_path_traversal(lines: list[str], finding: dict) -> Optional[PatchSpec]:
    """
    Replace raw path concatenation with os.path.realpath + allowlist check.
    """
    lineno = finding["line"] - 1
    line = lines[lineno]

    indent = len(line) - len(line.lstrip())
    prefix = " " * indent

    # Extract the variable being assigned to (filepath = ...)
    assign_re = re.search(r"^\s*(\w+)\s*=", line)
    if not assign_re:
        return None
    lhs = assign_re.group(1)

    # Try to find base_dir variable name from context (preceding few lines)
    base_var = "base_dir"
    for prev_line in lines[max(0, lineno - 5):lineno]:
        m = re.match(r"\s*(\w+)\s*=.*os\.path\.join.*__file__", prev_line)
        if m:
            base_var = m.group(1)
            break

    new_lines = [
        f"{prefix}# KAVACH-PATCH: path normalisation + containment check (CWE-22 fix)\n",
        f"{prefix}{lhs} = os.path.realpath(os.path.join({base_var}, filename))\n",
        f"{prefix}if not {lhs}.startswith(os.path.realpath({base_var})):\n",
        f"{prefix}    return 'Access denied', 403\n",
    ]
    return {
        "rationale": (
            "Replaced string concatenation with os.path.realpath() + a containment "
            "check that ensures the resolved path stays within the permitted base "
            "directory. Traversal sequences like ../ are collapsed before the check "
            "runs, preventing path traversal (CWE-22)."
        ),
        "old_lines": [line],
        "new_lines": new_lines,
        "line_number": finding["line"],
        "cwe": "CWE-22",
    }


# ── CWE-798: Hardcoded Credential ─────────────────────────────────────────────

def patch_hardcoded_cred(lines: list[str], finding: dict) -> Optional[PatchSpec]:
    """
    Replace a hardcoded string credential with an os.environ.get() lookup.
    """
    lineno = finding["line"] - 1
    line = lines[lineno]

    # Extract variable name and the hardcoded value
    assign_re = re.match(r"(\s*)(\w+)\s*=\s*['\"]([^'\"]+)['\"]", line)
    if not assign_re:
        return None

    indent_str = assign_re.group(1)
    var_name = assign_re.group(2)
    env_key = var_name.upper()

    new_lines = [
        f"{indent_str}# KAVACH-PATCH: load credential from environment variable (CWE-798 fix)\n",
        f"{indent_str}{var_name} = os.environ.get(\"{env_key}\")\n",
        f"{indent_str}if not {var_name}:\n",
        f'{indent_str}    raise RuntimeError("{env_key} environment variable is not set.")\n',
    ]
    return {
        "rationale": (
            f"Replaced hardcoded string literal with os.environ.get('{env_key}'). "
            "The secret is now loaded from the process environment at runtime, "
            "keeping it out of source code and version control (CWE-798)."
        ),
        "old_lines": [line],
        "new_lines": new_lines,
        "line_number": finding["line"],
        "cwe": "CWE-798",
    }

"""
Custom AST taint rules for Kavach-CRS.

Catches two classes that Bandit under-reports or misses:
  1. Hardcoded string literals assigned to credential-looking variable names (CWE-798)
  2. Path traversal built via string concatenation with + or os.path.join (CWE-22)

Returns a list of Finding dicts: {file, line, cwe, rule, snippet, confidence}
"""
import ast
from pathlib import Path
from typing import Any

# Variable name patterns that suggest credential storage
_CRED_NAMES = {
    "password", "passwd", "secret", "api_key", "apikey",
    "token", "auth_key", "admin_key", "private_key", "credential",
    "access_key", "secret_key",
}

# The CWE IDs this module reports
CWE_HARDCODED_CRED = "CWE-798"
CWE_PATH_TRAVERSAL = "CWE-22"


import re

def _mask_secret(snippet: str) -> str:
    # Find strings in quotes and mask them, but keep the first and last char
    return re.sub(r'([\'"])(.*?)\1', r'\1********\1', snippet)

class _CredentialVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]):
        self.findings: list[dict] = []
        self._lines = source_lines

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if name and any(c in name.lower() for c in _CRED_NAMES):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.findings.append({
                        "line": node.lineno,
                        "cwe": CWE_HARDCODED_CRED,
                        "rule": "hardcoded-credential",
                        "snippet": _mask_secret(self._lines[node.lineno - 1].rstrip()),
                        "confidence": "HIGH",
                    })
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        target = node.target
        name = None
        if isinstance(target, ast.Name):
            name = target.id
        if name and any(c in name.lower() for c in _CRED_NAMES):
            if node.value and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                self.findings.append({
                    "line": node.lineno,
                    "cwe": CWE_HARDCODED_CRED,
                    "rule": "hardcoded-credential",
                    "snippet": _mask_secret(self._lines[node.lineno - 1].rstrip()),
                    "confidence": "HIGH",
                })
        self.generic_visit(node)


class _PathTraversalVisitor(ast.NodeVisitor):
    """
    Catches patterns like:
      filepath = base_dir + "/" + user_input   (BinOp string concat)
      filepath = os.path.join(base, user_input) where user_input comes from request
    """
    def __init__(self, source_lines: list[str]):
        self.findings: list[dict] = []
        self._lines = source_lines
        # Track names assigned from request.args / request.form
        self._tainted: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> Any:
        # Track taint: `x = request.args.get(...)` or `x = request.form.get(...)`
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and func.attr == "get":
                if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
                    if func.value.value.id == "request":
                        for tgt in node.targets:
                            if isinstance(tgt, ast.Name):
                                self._tainted.add(tgt.id)

        # Detect: base_dir + "/" + tainted_var  (any BinOp concat chain)
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
            if self._binop_contains_tainted(node.value):
                self.findings.append({
                    "line": node.lineno,
                    "cwe": CWE_PATH_TRAVERSAL,
                    "rule": "path-traversal-concat",
                    "snippet": self._lines[node.lineno - 1].rstrip(),
                    "confidence": "MEDIUM",
                })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            if isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "path":
                if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "os":
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in self._tainted:
                            line_text = self._lines[node.lineno - 1].rstrip()
                            prev_line_text = self._lines[node.lineno - 2].rstrip() if node.lineno >= 2 else ""
                            if "# nosec" not in line_text and "# KAVACH-PATCH" not in line_text and "# KAVACH-PATCH" not in prev_line_text:
                                self.findings.append({
                                    "line": node.lineno,
                                    "cwe": CWE_PATH_TRAVERSAL,
                                    "rule": "path-traversal-join",
                                    "snippet": line_text,
                                    "confidence": "HIGH",
                                })
        self.generic_visit(node)

    def _binop_contains_tainted(self, node: ast.BinOp) -> bool:
        """Recursively check if any leaf Name in a BinOp is tainted."""
        def names(n: ast.expr) -> list[str]:
            if isinstance(n, ast.Name):
                return [n.id]
            if isinstance(n, ast.BinOp):
                return names(n.left) + names(n.right)
            return []
        return any(n in self._tainted for n in names(node))


class _SSRFVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]):
        self.findings: list[dict] = []
        self._lines = source_lines

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "post", "put", "delete", "request"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                self.findings.append({
                    "line": node.lineno,
                    "cwe": "CWE-918",
                    "rule": "ssrf-requests",
                    "snippet": self._lines[node.lineno - 1].rstrip(),
                    "confidence": "HIGH",
                })
        self.generic_visit(node)


def run_custom_rules(filepath: str) -> list[dict]:
    """
    Run all custom AST rules against a single Python file.
    Returns a list of finding dicts with keys: file, line, cwe, rule, snippet, confidence.
    """
    source = Path(filepath).read_text(encoding="utf-8-sig")
    lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    findings: list[dict] = []

    cred_v = _CredentialVisitor(lines)
    cred_v.visit(tree)
    findings.extend(cred_v.findings)

    path_v = _PathTraversalVisitor(lines)
    path_v.visit(tree)
    findings.extend(path_v.findings)

    ssrf_v = _SSRFVisitor(lines)
    ssrf_v.visit(tree)
    findings.extend(ssrf_v.findings)

    for f in findings:
        f["file"] = str(filepath)

    return findings


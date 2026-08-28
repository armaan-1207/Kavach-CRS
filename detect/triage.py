"""
TRIAGE stage -” Kavach-CRS

Two passes:
  1. Reachability filter  -” discard findings in functions that are never
     called from a Flask route or main() entry point.
  2. Mission-impact sort  -” order surviving findings by operator-declared
     criticality tier (mission_impact.yaml), highest first.

This is the "watch it discard the unreachable finding live" demo step.
"""
import ast
from pathlib import Path
from typing import Any
import yaml
import itertools


# -- 1. Call-graph reachability ----------------------------------------------

class _CallGraphBuilder(ast.NodeVisitor):
    """
    Walks an AST and builds:
      self.entry_points  -” set of function names that are Flask routes or main()
      self.call_edges    -” {caller: {callee, callee, ...}}
    """

    def __init__(self):
        self.entry_points: set[str] = set()
        self.call_edges: dict[str, set[str]] = {}
        self._current_func: str | None = None

    # Detect Flask @app.route decorators â†’ mark function as entry point
    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        prev = self._current_func
        self._current_func = node.name
        self.call_edges.setdefault(node.name, set())

        for dec in node.decorator_list:
            if _is_route_decorator(dec):
                self.entry_points.add(node.name)
            # Also treat @app.before_request etc.
            if isinstance(dec, ast.Attribute) and dec.attr in (
                "before_request", "after_request", "teardown_request"
            ):
                self.entry_points.add(node.name)

        if node.name == "main":
            self.entry_points.add("main")

        self.generic_visit(node)
        self._current_func = prev

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> Any:
        if self._current_func is None:
            self.generic_visit(node)
            return
        callee = _extract_call_name(node.func)
        if callee:
            self.call_edges[self._current_func].add(callee)
        self.generic_visit(node)


def _is_route_decorator(node: ast.expr) -> bool:
    """True if decorator looks like @app.route(...)."""
    if isinstance(node, ast.Call):
        return _is_route_decorator(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr == "route"
    return False


def _extract_call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _reachable_functions(entry_points: set[str], edges: dict[str, set[str]]) -> set[str]:
    """BFS/DFS from entry points through call graph."""
    visited: set[str] = set(entry_points)
    queue = list(entry_points)
    while queue:
        current = queue.pop()
        for callee in edges.get(current, set()):
            if callee not in visited:
                visited.add(callee)
                queue.append(callee)
    return visited


def build_reachability(target_path: str) -> set[str]:
    """
    Parse all .py files under target_path, build call graph,
    return the set of reachable function names.
    """
    root = Path(target_path)
    py_files = list(itertools.islice(root.rglob("*.py"), 5000)) if root.is_dir() else [root]

    all_entries: set[str] = set()
    all_edges: dict[str, set[str]] = {}

    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue
        builder = _CallGraphBuilder()
        builder.visit(tree)
        all_entries |= builder.entry_points
        for fn, callees in builder.call_edges.items():
            all_edges.setdefault(fn, set()).update(callees)

    return _reachable_functions(all_entries, all_edges)


def _enclosing_function(finding: dict, target_path: str) -> str | None:
    """
    Find which function the finding's line is inside, by parsing the file.
    Returns the function name, or None if at module level.
    """
    try:
        source = Path(finding["file"]).read_text(encoding="utf-8-sig")
        tree = ast.parse(source)
    except Exception:
        return None

    best: str | None = None
    best_start = -1

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not hasattr(node, "end_lineno"):
                continue
            if node.lineno <= finding["line"] <= node.end_lineno:
                if node.lineno > best_start:
                    best_start = node.lineno
                    best = node.name

    return best


# -- 2. Mission-impact sorting ------------------------------------------------

def _load_mission_impact(config_path: str) -> dict[str, int]:
    """Load mission_impact.yaml and return {function_name: tier}."""
    p = Path(config_path)
    if not p.exists():
        return {}
    with open(p, encoding="utf-8-sig") as fh:
        data = yaml.safe_load(fh)
    services = data.get("services", {})
    out = {}
        for k, v in services.items():
            try:
                out[k] = int(v)
            except ValueError:
                print(f"Warning: mission_impact.yaml invalid tier for {k}: {v}. Defaulting to 3.")
                out[k] = 3
        return out


# -- Main triage entry point --------------------------------------------------

def run_triage(
    findings: list[dict],
    target_path: str,
    mission_impact_path: str = "mission_impact.yaml",
) -> tuple[list[dict], list[dict]]:
    """
    Returns (survivors, discarded).

    survivors  -” findings in reachable code, sorted by mission-impact tier.
    discarded  -” findings filtered out because their enclosing function is
                 not reachable from any entry point.
    """
    if reachable is None:
        reachable = build_reachability(target_path)
    impact = _load_mission_impact(mission_impact_path)
    default_tier = impact.get("default", 2)

    survivors: list[dict] = []
    discarded: list[dict] = []

    for finding in findings:
        fn = _enclosing_function(finding, target_path)
        finding["enclosing_function"] = fn

        if fn is not None and fn not in reachable:
            finding["triage_status"] = "DISCARDED_UNREACHABLE"
            finding["triage_reason"] = (
                f"Function '{fn}' is not reachable from any entry point."
            )
            discarded.append(finding)
        else:
            tier = impact.get(fn, default_tier) if fn else default_tier
            finding["mission_tier"] = tier
            finding["triage_status"] = "ACTIVE"
            survivors.append(finding)

    # Sort survivors: tier 1 first, then by severity
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    survivors.sort(
        key=lambda f: (f.get("mission_tier", 2), sev_order.get(f.get("severity", "MEDIUM"), 1))
    )

    return survivors, discarded


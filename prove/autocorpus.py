import ast
import yaml
from pathlib import Path
import os

def extract_routes_and_params(filepath: str) -> list[dict]:
    """Parse Flask AST and extract routes and their accessed request parameters."""
    try:
        source = Path(filepath).read_text(encoding="utf-8-sig")
        tree = ast.parse(source)
    except Exception:
        return []

    routes = []
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, getattr(ast, "AsyncFunctionDef", type(None)))):
            route_path = None
            method = "GET"
            # Find @app.route
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "route":
                    if decorator.args and isinstance(decorator.args[0], ast.Constant):
                        route_path = decorator.args[0].value
                    for kw in decorator.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, ast.List):
                            for m in kw.value.elts:
                                if isinstance(m, ast.Constant):
                                    method = m.value
                                    break
            
            if route_path:
                params = set()
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "get":
                        if isinstance(child.func.value, ast.Attribute) and child.func.value.attr in ("args", "form", "values"):
                            if isinstance(child.func.value.value, ast.Name) and child.func.value.value.id == "request":
                                if child.args and isinstance(child.args[0], ast.Constant):
                                    params.add(child.args[0].value)
                    elif isinstance(child, ast.Subscript):
                        if isinstance(child.value, ast.Attribute) and child.value.attr in ("args", "form", "values"):
                            if isinstance(child.value.value, ast.Name) and child.value.value.id == "request":
                                if isinstance(child.slice, ast.Constant):
                                    params.add(child.slice.value)
                
                routes.append({
                    "route": route_path,
                    "method": method,
                    "params": list(params)
                })
    
    return routes

def generate_corpus_yaml(routes: list[dict]) -> str:
    """Generate a cases.yaml string matching the required differential schema."""
    corpus = {"cases": []}
    
    case_idx = 1
    for r in routes:
        route = r["route"]
        method = r["method"]
        params = r["params"]
        
        if not params:
            continue
            
        # Base case
        safe_case = {
            "id": f"dyn_safe_{case_idx}",
            "cwe_class": "ALL",
            "exploit": False,
            "route": route,
            "method": method,
            "input": {p: "test_value" for p in params}
        }
        corpus["cases"].append(safe_case)
        
        # Generic exploits
        cwes = [
            ("CWE-89", "1' OR 1=1--"),
            ("CWE-78", "127.0.0.1; whoami"),
            ("CWE-22", "../../../../etc/passwd"),
            ("CWE-918", "http://169.254.169.254/latest/meta-data/"),
            ("CWE-94", "{{7*7}}")
        ]
        
        for cwe, payload in cwes:
            exp_case = {
                "id": f"dyn_exp_{case_idx}_{cwe.lower()}",
                "cwe_class": cwe,
                "exploit": True,
                "route": route,
                "method": method,
                "input": {p: payload for p in params}
            }
            corpus["cases"].append(exp_case)
            
        case_idx += 1
            
    return yaml.dump(corpus, sort_keys=False)

def build_dynamic_corpus(target_file: str, out_path: str) -> None:
    routes = extract_routes_and_params(target_file)
    if not routes:
        return
    yaml_str = generate_corpus_yaml(routes)
    if os.path.dirname(out_path):
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
    Path(out_path).write_text(yaml_str, encoding="utf-8")

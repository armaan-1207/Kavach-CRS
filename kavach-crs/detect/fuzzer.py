import json
import os
import subprocess
import sys
from pathlib import Path
import uuid

def run_atheris_fuzzer(target_path: str, reachable_funcs: set[str]) -> list[dict]:
    """
    Run Atheris targeted fuzzing on the target Flask app.
    Generates a targeted harness, runs it in a subprocess, and parses crashes.
    """
    try:
        import atheris
    except ImportError:
        print("  ⚠  Atheris not installed on this OS. Skipping Fuzzer stage.")
        return []

    print("  ►  Atheris found. Fuzzing reachable entry points...")
    target = Path(target_path).resolve()
    target_dir = target.parent
    run_output_dir = target_dir.parent / "run_output"
    run_output_dir.mkdir(exist_ok=True)
    
    findings_file = run_output_dir / f"fuzz_findings_{uuid.uuid4().hex[:8]}.json"

    # Write a dynamic fuzzer harness that imports the target and fuzzes its routes
    kavach_root = Path(__file__).parent.parent.resolve()
    harness_code = f"""
import sys
import os
import atheris
import json
import traceback
import importlib

# 1. HARDEN THE HARNESS: Prevent fuzzer from executing real shell commands against the host
sys.path.insert(0, {str(kavach_root)!r})
from prove.worker import _install_subprocess_stub, _harden_environment
_install_subprocess_stub()
_harden_environment()

# 2. SAFE PATH INJECTION: Use repr() to prevent f-string code injection
target_dir = {str(target_dir)!r}
target_module = {target.stem!r}

with atheris.instrument_imports():
    sys.path.insert(0, target_dir)
    target_app = importlib.import_module(target_module)

app = getattr(target_app, 'app', None)
if not app:
    sys.exit(0)

app.config['PROPAGATE_EXCEPTIONS'] = True
client = app.test_client()
findings = []

# Dynamically extract all GET routes
routes = []
for rule in app.url_map.iter_rules():
    if 'GET' in rule.methods and rule.rule != '/static/<path:filename>':
        routes.append(rule.rule)

if not routes:
    sys.exit(0)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    route = fdp.PickValueInList(routes)
    payload = fdp.ConsumeUnicodeNoSurrogates(100)
    
    try:
        # We append random query parameters to fuzz inputs
        client.get(f"{route}?username={payload}&host={payload}&name={payload}&key={payload}")
    except Exception as e:
        # Catch exceptions (e.g. SQLi crashes, Command Injection errors)
        err_str = str(e)
        target_path_str = {str(target)!r}
        finding = {{
            "id": "FUZZ_" + str(len(findings)),
            "file": target_path_str,
            "line": 0, # Dynamic
            "cwe": "CWE-UNKNOWN",
            "rule": "atheris_crash",
            "severity": "HIGH",
            "confidence": "HIGH",
            "snippet": err_str,
            "source": "atheris"
        }}
        
        # Best effort CWE mapping based on exception type
        if "sqlite" in err_str.lower():
            finding["cwe"] = "CWE-89"
        elif "CalledProcessError" in err_str:
            finding["cwe"] = "CWE-78"
            
        findings.append(finding)
        
        # Stop early if we found enough to prove it works
        if len(findings) >= 5:
            findings_file_path = {str(findings_file)!r}
            with open(findings_file_path, 'w') as f:
                json.dump(findings, f)
            sys.exit(0)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
"""

    harness_path = run_output_dir / "fuzz_harness.py"
    harness_path.write_text(harness_code, encoding="utf-8")

    # Pass a restricted environment identical to prove/differential.py
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "ADMIN_SECRET": os.environ.get("ADMIN_SECRET", ""),
    }

    # Run the fuzzer harness in a subprocess
    try:
        subprocess.run(
            [sys.executable, str(harness_path), "-runs=1000", "-max_total_time=15"],
            timeout=20,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"  ⚠  Fuzzer harness failed: {e}")

    findings = []
    if findings_file.exists():
        try:
            findings = json.loads(findings_file.read_text(encoding="utf-8"))
            findings_file.unlink()
        except Exception:
            pass

    # Clean up harness
    if harness_path.exists():
        harness_path.unlink()

    return findings

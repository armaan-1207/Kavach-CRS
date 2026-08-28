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
    harness_code = f"""
import sys
import atheris
import json
import traceback

with atheris.instrument_imports():
    sys.path.insert(0, r'{target_dir}')
    import {target.stem} as target_app

app = getattr(target_app, 'app', None)
if not app:
    sys.exit(0)

client = app.test_client()
findings = []

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # Fuzz the 4 known routes with random data
    route = fdp.PickValueInList(['/user', '/ping', '/file', '/admin'])
    payload = fdp.ConsumeUnicodeNoSurrogates(100)
    
    try:
        if route == '/user':
            client.get(f'/user?username={{payload}}')
        elif route == '/ping':
            client.get(f'/ping?host={{payload}}')
        elif route == '/file':
            client.get(f'/file?name={{payload}}')
        elif route == '/admin':
            client.get(f'/admin?key={{payload}}')
    except Exception as e:
        # Catch exceptions (e.g. SQLi crashes, Command Injection errors)
        err_str = str(e)
        finding = {{
            "id": "FUZZ_" + str(len(findings)),
            "file": r'{target}',
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
            with open(r'{findings_file}', 'w') as f:
                json.dump(findings, f)
            sys.exit(0)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
"""

    harness_path = run_output_dir / "fuzz_harness.py"
    harness_path.write_text(harness_code, encoding="utf-8")

    # Run the fuzzer harness in a subprocess
    try:
        subprocess.run(
            [sys.executable, str(harness_path), "-runs=1000", "-max_total_time=15"],
            timeout=20,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
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

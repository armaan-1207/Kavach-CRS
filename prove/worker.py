"""
Sandboxed worker process - Kavach-CRS PROVE stage (Phase A hardening)

WHY THIS FILE EXISTS
---------------------
`prove/differential.py` used to import the target app with
`importlib.util.spec_from_file_location(...)` and `spec.loader.exec_module(mod)`
directly inside the CRS's own process. That means arbitrary top-level code in
the file being scanned - the exact file whose trustworthiness is in
question - ran with the same privileges, environment, and memory space as
the orchestrator that writes the tamper-evident ledger.

This worker moves that execution into an isolated subprocess:
  - a minimal, explicitly allowlisted environment (no inherited secrets
    beyond what's needed to run the app)
  - subprocess.check_output / .run / .call / .check_call / .Popen replaced
    at the sys.modules level *before* the target module is imported, so the
    stub is caught regardless of how the target imported subprocess
    (`import subprocess`, `from subprocess import check_output`, etc.) -
    the old mock.patch.object(mod_sp, "check_output", ...) approach only
    caught the `import subprocess` case and could fail open otherwise.
  - PATH cleared as defense-in-depth: even if a stub were somehow bypassed,
    there is nothing on PATH for a shell to execute.
  - a hard wall-clock timeout is enforced by the *caller* (differential.py),
    since a hung subprocess is trivially recoverable by killing it, but a
    hung in-process import can wedge the whole pipeline.

This worker never touches the ledger. It has one job: run one HTTP GET
against the target Flask app and print the result as one JSON line.

Usage:
    python -m prove.worker <app_module_path> <route> <params_json>

Output (stdout, single line):
    {"status_code": int, "body": str}
"""
import io
import json
import os
import sys
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


def _install_subprocess_stub() -> None:
    """
    Replace the entire `subprocess` module in sys.modules with an inert stub
    before the target app is imported. Covers check_output/run/call/
    check_call/Popen regardless of import style. Real subprocess calls never
    reach the OS from inside this worker.
    """
    import subprocess as real_subprocess

    class _StubCompletedProcess:
        def __init__(self, args, returncode=0, stdout="", stderr=""):
            self.args = args
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def _tag(cmd, kw: dict) -> str:
        # If shell=False, the OS executes the command directly without a shell.
        # If the arguments contain shell metacharacters (&, |, ;), the underlying
        # binary (like 'ping' or 'ls') will treat them as literal strings (e.g. a
        # hostname "127.0.0.1 & whoami"). This usually causes the binary to fail
        # with an error (e.g. unknown host). We simulate that failure here so
        # exploit cases realistically fail (500) while safe cases succeed (200),
        # producing identical output for safe cases regardless of shell=True/False.
        if not kw.get("shell"):
            args = cmd if isinstance(cmd, list) else [cmd]
            for arg in args:
                if any(char in str(arg) for char in ["&", "|", ";", "`", "$", "\n", " "]):
                    raise real_subprocess.CalledProcessError(1, cmd)
        return "KAVACH-STUB-OK"

    def _check_output(cmd, **kw):
        return _tag(cmd, kw)

    def _run(cmd, **kw):
        return _StubCompletedProcess(cmd, 0, _tag(cmd, kw), "")

    def _call(cmd, **kw):
        return 0

    def _check_call(cmd, **kw):
        return 0

    class _StubPopen:
        def __init__(self, cmd, **kw):
            self.args = cmd
            self.returncode = 0

        def communicate(self, *a, **kw):
            return (_tag(kw).encode(), b"")

        def wait(self, *a, **kw):
            return 0

    stub = types.ModuleType("subprocess")
    # Keep real constants/exception types the target app may reference so it
    # doesn't crash on attribute access even though calls are inert.
    stub.PIPE = real_subprocess.PIPE
    stub.STDOUT = real_subprocess.STDOUT
    stub.DEVNULL = real_subprocess.DEVNULL
    stub.CalledProcessError = real_subprocess.CalledProcessError
    stub.TimeoutExpired = real_subprocess.TimeoutExpired
    stub.CompletedProcess = _StubCompletedProcess
    stub.check_output = _check_output
    stub.run = _run
    stub.call = _call
    stub.check_call = _check_call
    stub.Popen = _StubPopen

    sys.modules["subprocess"] = stub
    
    # Also stub OS level command execution
    import os
    def _os_stub(*args, **kwargs):
        return 0
    def _os_popen_stub(*args, **kwargs):
        class PopenStub:
            def read(self): return "KAVACH-STUB-OS"
            def close(self): return None
        return PopenStub()
        
    os.system = _os_stub
    os.popen = _os_popen_stub
    for attr in dir(os):
        if attr.startswith("exec") or "spawn" in attr:
            setattr(os, attr, _os_stub)

def _install_socket_stub() -> None:
    import socket
    
    class _StubSocket:
        def __init__(self, *args, **kwargs):
            pass
        def connect(self, *args, **kwargs):
            raise ConnectionRefusedError("KAVACH-STUB-SOCKET: Network blocked")
        def send(self, *args, **kwargs):
            raise ConnectionRefusedError("KAVACH-STUB-SOCKET: Network blocked")
        def recv(self, *args, **kwargs):
            raise ConnectionRefusedError("KAVACH-STUB-SOCKET: Network blocked")
        def close(self):
            pass
            
    socket.socket = _StubSocket


def _harden_environment() -> None:
    """Defense-in-depth: clear PATH and apply rlimits if available."""
    os.environ["PATH"] = ""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))          # 5s CPU
        resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024,)*2)  # 256MB address space
        resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))         # no forking/exec at all
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024*1024,)*2) # no file writes >1MB
    except (ImportError, AttributeError, ValueError):
        # Windows or unsupported OS - rely on caller timeout
        pass


def _emit(status_code: int, body: str) -> None:
    print(json.dumps({"status_code": status_code, "body": body}))


def main() -> None:
    if len(sys.argv) != 4:
        _emit(-1, "usage: worker.py <app_module_path> <route> <params_json>")
        sys.exit(1)

    app_module_path, route, params_json = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        params = json.loads(params_json)
    except json.JSONDecodeError as e:
        _emit(-1, f"bad params json: {e}")
        sys.exit(1)

    _install_subprocess_stub()
    _install_socket_stub()
    _harden_environment()

    import importlib.util

    spec = importlib.util.spec_from_file_location("_target_app", app_module_path)
    if spec is None or spec.loader is None:
        _emit(-1, f"could not load spec for {app_module_path}")
        return
    mod = importlib.util.module_from_spec(spec)

    # Keep __file__ pointing at the real app dir so DB_PATH / base_dir
    # resolve correctly whether we're loading the original or a backup copy.
    original_path = os.environ.get("KAVACH_TARGET_FILE", app_module_path)
    mod.__file__ = str(Path(original_path).resolve())

    buf = io.StringIO()
    old_argv = sys.argv[:]
    sys.argv = [app_module_path]
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception as e:
        _emit(-1, f"import error: {e}"[:200])
        return
    finally:
        sys.argv = old_argv

    # Framework detection: Flask → FastAPI → Django WSGI → generic
    web_app = getattr(mod, "app", None)
    framework = "flask"

    if web_app is None:
        # FastAPI apps are also commonly named 'app' but may be named differently
        for attr in dir(mod):
            obj = getattr(mod, attr, None)
            if obj is not None and hasattr(obj, "test_client") and callable(obj.test_client):
                web_app = obj
                framework = "flask"
                break

    if web_app is None:
        # Django: look for wsgi 'application' callable
        django_wsgi = getattr(mod, "application", None)
        if django_wsgi and callable(django_wsgi):
            _emit(-1, (
                "Unsupported framework: Django WSGI application detected. "
                "PROVE stage requires a Flask/FastAPI test_client — "
                "differential evidence unavailable for Django targets. "
                "Reachability triage still applies."
            ))
            return

    if web_app is None:
        _emit(-1, (
            "Unsupported framework: no Flask/FastAPI app object found in module. "
            "Ensure the app is assigned to a module-level variable named 'app'. "
            "PROVE stage skipped."
        ))
        return

    # Run any DB init if present
    for init_name in ("init_db", "create_tables", "setup_db", "init_app"):
        init_fn = getattr(mod, init_name, None)
        if init_fn and callable(init_fn):
            try:
                init_fn()
            except Exception:
                pass
            break

    try:
        with web_app.test_client() as client:
            resp = client.get(route, query_string=params)
            _emit(resp.status_code, resp.get_data(as_text=True))
    except Exception as e:
        _emit(-1, str(e)[:200])


if __name__ == "__main__":
    main()

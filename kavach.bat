@echo off
setlocal
echo ================================================================
echo   KAVACH-CRS -- Cyber Reasoning System (Air-Gapped Bootstrap)
echo ================================================================
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.10+ is required.
    exit /b 1
)

if not exist ".venv" (
    echo [*] Creating isolated virtual environment...
    python -m venv .venv
)

echo [*] Activating environment and verifying dependencies...
call .venv\Scripts\activate
pip install -r requirements.txt --quiet --disable-pip-version-check

echo [*] Bootstrapping Kavach-CRS...
python cli.py %*

@echo off
REM Olive quickstart — one command to see the full demo
REM Usage: quickstart.bat

echo.
echo   ██████  ██      ██ ██    ██ ███████
echo  ██    ██ ██      ██ ██    ██ ██
echo  ██    ██ ██      ██ ██    ██ █████
echo  ██    ██ ██      ██  ██  ██  ██
echo   ██████  ███████ ██   ████   ███████
echo.
echo   Zero-trust runtime security gateway for AI agents
echo.

REM ── 1. Check Python ──────────────────────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python 3.11+ is required. Install from https://python.org
    exit /b 1
)
python --version

REM ── 2. Install dependencies ──────────────────────────────────────────────────
echo.
echo Installing Olive and dependencies...
python -m pip install -e ".[dev]" -q

REM ── 3. Run the live demo ──────────────────────────────────────────────────────
echo.
echo Starting live demo...
echo   -^> Dashboard will open at http://127.0.0.1:7799
echo   -^> Watch agents appear, attacks get blocked, modes escalate
echo   -^> Press Ctrl+C to stop
echo.

python demo/live_demo.py

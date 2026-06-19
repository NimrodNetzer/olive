#!/usr/bin/env bash
# Olive quickstart — one command to see the full demo
# Usage: ./quickstart.sh
set -e

echo ""
echo "  ██████  ██      ██ ██    ██ ███████"
echo " ██    ██ ██      ██ ██    ██ ██     "
echo " ██    ██ ██      ██ ██    ██ █████  "
echo " ██    ██ ██      ██  ██  ██  ██     "
echo "  ██████  ███████ ██   ████   ███████"
echo ""
echo "  Zero-trust runtime security gateway for AI agents"
echo "  https://github.com/NimrodNetzer/olive"
echo ""

# ── 1. Check Python ──────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
  echo "ERROR: Python 3.11+ is required. Install from https://python.org"
  exit 1
fi
PY=${PYTHON:-$(command -v python3 2>/dev/null || command -v python)}
echo "Python: $($PY --version)"

# ── 2. Install dependencies (editable, into the current venv / system env) ───
echo ""
echo "Installing Olive and dependencies..."
$PY -m pip install -e ".[dev]" -q

# ── 3. Run the live demo ──────────────────────────────────────────────────────
echo ""
echo "Starting live demo..."
echo "  → Dashboard will open at http://127.0.0.1:7799"
echo "  → Watch agents appear, attacks get blocked, modes escalate"
echo "  → Press Ctrl+C to stop"
echo ""

$PY demo/live_demo.py

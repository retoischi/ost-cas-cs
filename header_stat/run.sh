#!/usr/bin/env bash
set -e

ulimit -n unlimited >/dev/null 2>&1 || true

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/.venv"
PYTHON=python3.13
STAMP="$VENV/.deps_installed"

# venv anlegen
if [ ! -d "$VENV" ]; then
  "$PYTHON" -m venv "$VENV"
fi

PY="$VENV/bin/python"
PIP="$VENV/bin/pip"

# deps nur einmal installieren
if [ ! -f "$STAMP" ]; then
  $PIP install -U pip setuptools >/dev/null
  $PIP install aiohttp uvloop aiodns >/dev/null

  export PYCARES_USE_SYSTEM_LIB=1
  $PIP install \
    --force-reinstall \
    --no-binary=pycares \
    --no-build-isolation \
    --no-cache-dir \
    pycares==4.11.0 >/dev/null

  touch "$STAMP"
fi

exec "$PY" "$@"


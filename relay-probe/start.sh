#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python -m app.main
fi
exec "${PYTHON:-python3}" -m app.main

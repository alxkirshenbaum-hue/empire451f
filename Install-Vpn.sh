#!/bin/bash
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="${EMPIRE_PYTHON:-}"
if [ -z "$PYTHON" ]; then
 for candidate in /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)' 2>/dev/null; then PYTHON="$candidate"; break; fi
 done
fi
if [ -z "$PYTHON" ]; then echo 'Python 3.12+ missing. Run the README bootstrap command.' >&2; exit 1; fi
exec "$PYTHON" -B "$SCRIPT_DIR/client.py" "$@"

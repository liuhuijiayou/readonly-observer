#!/usr/bin/env bash
# Linux bootstrap only. All secret input belongs to Observer's hidden TTY CLI.
set +x
set -euo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PYTHON_BIN=''
ARGS=("$@")
for ((i=0; i<${#ARGS[@]}; i++)); do
  if [[ ${ARGS[i]} == --python ]]; then
    ((i+1 < ${#ARGS[@]})) || { printf '%s\n' 'Missing --python path.' >&2; exit 2; }
    PYTHON_BIN=${ARGS[i+1]}
  fi
done
if [[ -z $PYTHON_BIN ]]; then
  for candidate in python3.14 python3.15 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -I -c 'import sys;sys.exit(sys.version_info < (3,14))' >/dev/null 2>&1; then
      PYTHON_BIN=$(command -v "$candidate")
      break
    fi
  done
fi
if [[ -z $PYTHON_BIN ]]; then
  printf '%s\n' 'Python 3.14+ with venv/ensurepip is required; use --python /absolute/python.' 'Usage: install_linux_node.sh [--help] [--dry-run] [--no-start] [metadata options]' >&2
  exit 2
fi
exec "$PYTHON_BIN" -I -B "$SCRIPT_DIR/linux_node.py" install "$@"

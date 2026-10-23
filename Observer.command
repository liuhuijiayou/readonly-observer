#!/bin/sh
set -eu
observer_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ ! -x "$observer_dir/.venv/bin/python" ]; then
    printf '%s\n' 'Create .venv with Python 3.14 and install this project first. See README.md.'
    exit 2
fi
# Legacy state requires explicit instance selection; never open a different profile silently.
if [ -e "$observer_dir/.local/observer-control" ] || [ -L "$observer_dir/.local/observer-control" ]; then
    printf '%s\n' 'Legacy operator state detected. Refusing to open a new empty instance.'
    printf '%s\n' 'Use the installed observer CLI with an explicit --home and menu. See docs/migration.md.'
    exit 2
fi
printf '%s\n' 'Opening the new CLI instance menu. It has no sources until you explicitly approve them; this does not control a legacy terminal client.'
if [ -n "${OBSERVER_HOME:-}" ]; then
    set -- --home "$OBSERVER_HOME" menu
else
    set -- menu
fi
exec /usr/bin/env -i PATH=/usr/bin:/bin "$observer_dir/.venv/bin/python" -I -B -c 'import sys;sys.path.insert(0,sys.argv.pop(1));from observer.cli import main;raise SystemExit(main())' "$observer_dir/src" "$@"

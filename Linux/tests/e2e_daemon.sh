#!/bin/bash
# The ProxyBridge service (ProxyBridge --daemon): protocol, access control, profile store, engine control and routing, as root.
#   sudo Linux/tests/e2e_daemon.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export PB_DIR LD_LIBRARY_PATH="$PB_DIR"
exec python3 "$HERE/e2e_daemon.py" "$@"

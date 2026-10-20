#!/bin/bash
# The ProxyBridge service under real systemd, with the exact unit the installer writes (sandboxing included): it starts, creates its
# socket, loads the eBPF programs, routes traffic, keeps its profiles, restarts after a crash and stops cleanly.
# Uses a volatile unit (/run/systemd/system) and a copy of the program under /opt; nothing is left behind.
#   sudo Linux/tests/e2e_service.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -d /run/systemd/system ] || { echo "SKIP: systemd is not running here"; exit 0; }
[ ! -e /run/proxybridge/ctl.sock ] || { echo "SKIP: a ProxyBridge service is already running here"; exit 0; }
export PB_DIR
exec python3 "$HERE/e2e_service.py"

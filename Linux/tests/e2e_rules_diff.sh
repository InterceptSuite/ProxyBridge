#!/bin/bash
# Differential rule test: random rule sets, random destinations, kernel fast path + slow path vs an independent reference.
#   sudo Linux/tests/e2e_rules_diff.sh [seeds] [probes per protocol]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"
ip route add unreachable 198.18.0.0/15 2>/dev/null; ROUTE=$?
trap 'kill $FAKE 2>/dev/null; wait 2>/dev/null; [ "$ROUTE" = 0 ] && ip route del unreachable 198.18.0.0/15 2>/dev/null; rm -rf "$WORK"' EXIT
python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & FAKE=$!
sleep 1
python3 "$HERE/rules_diff.py" "$PB_DIR" "${1:-8}" "${2:-300}"

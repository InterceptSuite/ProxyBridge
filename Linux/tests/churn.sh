#!/bin/bash
# Rule/proxy churn with live traffic. Needs root, curl, python3, gcc.   sudo tests/churn.sh [iterations]
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR"; exit 1; }
WORK=$(mktemp -d); trap 'kill $FAKE $TRAFFIC 2>/dev/null; wait 2>/dev/null; rm -rf $WORK' EXIT
gcc -Wall -Wextra -O1 -g -I"$ROOT/src" -o "$WORK/churn_test" "$HERE/churn_test.c" -L"$PB_DIR" -lproxybridge -lpthread || exit 1
python3 "$HERE/fake_proxies.py" "$WORK/log" >/dev/null 2>&1 & FAKE=$!
sleep 1
( while :; do
    curl -s -m 2 http://192.0.2.5/ >/dev/null
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
s.sendto(b'x', ('192.0.2.9', 5300)); s.recv(100)" 2>/dev/null
  done ) & TRAFFIC=$!
env LD_LIBRARY_PATH="$PB_DIR" ${PB_PRELOAD:+LD_PRELOAD="$PB_PRELOAD" PB_SANITIZED=1} "$WORK/churn_test" "${1:-3000}"

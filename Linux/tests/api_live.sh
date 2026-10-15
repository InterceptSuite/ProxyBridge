#!/bin/bash
# Library API against the live datapath. Needs root, curl, python3, gcc.   sudo tests/api_live.sh
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
WORK=$(mktemp -d); trap 'kill $FAKE 2>/dev/null; wait 2>/dev/null; rm -rf $WORK' EXIT
gcc -Wall -Wextra -O1 -g -I"$ROOT/src" -o "$WORK/api_live_test" "$HERE/api_live_test.c" -L"$PB_DIR" -lproxybridge -lpthread || exit 1
python3 "$HERE/fake_proxies.py" "$WORK/log" >/dev/null 2>&1 & FAKE=$!
sleep 1
env LD_LIBRARY_PATH="$PB_DIR" ${PB_PRELOAD:+LD_PRELOAD="$PB_PRELOAD"} "$WORK/api_live_test"

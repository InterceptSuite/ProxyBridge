#!/bin/bash
# Library API against the live datapath. Needs root, curl, python3, gcc.   sudo tests/api_live.sh
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
WORK=$(mktemp -d); trap 'kill $FAKE 2>/dev/null; wait 2>/dev/null; rm -rf $WORK' EXIT
gcc -Wall -Wextra -O1 -g -I"$ROOT/src" -o "$WORK/api_live_test" "$HERE/api_live_test.c" -L"$ROOT/src" -lproxybridge -lpthread || exit 1
python3 "$HERE/fake_proxies.py" "$WORK/log" >/dev/null 2>&1 & FAKE=$!
sleep 1
LD_LIBRARY_PATH="$ROOT/src" "$WORK/api_live_test"

#!/bin/bash
# usage: tests/run_tests.sh [outdir]   (root-free)
set -e
cd "$(dirname "$0")/.."
OUT="${1:-$(mktemp -d)}"
CF="-Wall -Wextra -Wno-unused-parameter -g -fsanitize=address,undefined -I../src -I. -D_GNU_SOURCE $(pkg-config --cflags gtk+-3.0)"
LF="$(pkg-config --libs gtk+-3.0)"
gcc $CF tests/config_test.c gui_config.c -o "$OUT/config_test" $LF
gcc $CF tests/json_test.c gui_json.c -o "$OUT/json_test" $LF
gcc -O1 -I../src -I. -D_GNU_SOURCE $(pkg-config --cflags gtk+-3.0) tests/config_test.c gui_config.c -o "$OUT/config_plain" $LF
"$OUT/config_plain"
ASAN_OPTIONS=detect_leaks=1 "$OUT/config_test"
ASAN_OPTIONS=detect_leaks=1 "$OUT/json_test"

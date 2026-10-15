#!/bin/bash
# Builds profile_test with ASan+UBSan (and plain, warnings as errors) and runs it. Output goes to a temp dir.
set -euo pipefail
cd "$(dirname "$0")"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -Werror"
gcc $CFLAGS -o "$OUT/plain" profile_test.c ../pb_profile.c
gcc $CFLAGS -fsanitize=address,undefined -fno-sanitize-recover=undefined -o "$OUT/asan" profile_test.c ../pb_profile.c
"$OUT/plain"
ASAN_OPTIONS=detect_leaks=1 "$OUT/asan"

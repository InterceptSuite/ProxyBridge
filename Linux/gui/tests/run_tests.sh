#!/bin/bash
# usage: tests/run_tests.sh [outdir]   (root-free)
set -e
cd "$(dirname "$0")/.."
OUT="${1:-$(mktemp -d)}"
CF="-Wall -Wextra -Wno-unused-parameter -g -fsanitize=address,undefined -I../src -I../profile -I. -D_GNU_SOURCE $(pkg-config --cflags gtk+-3.0)"
LF="$(pkg-config --libs gtk+-3.0)"
gcc $CF tests/config_test.c gui_config.c ../profile/pb_profile.c -o "$OUT/config_test" $LF
gcc $CF tests/json_test.c gui_json.c -o "$OUT/json_test" $LF
gcc -g -Wall -Wextra -fsanitize=address,undefined -DPB_TEST_HOOKS -D_GNU_SOURCE -I. -I../src $(pkg-config --cflags glib-2.0) tests/boot_test.c gui_boot.c ../src/pb_unit.c -o "$OUT/boot_test" $(pkg-config --libs glib-2.0)
gcc $CF tests/list_test.c gui_list.c -o "$OUT/list_test" $LF
gcc -O1 -I../src -I../profile -I. -D_GNU_SOURCE $(pkg-config --cflags gtk+-3.0) tests/config_test.c gui_config.c ../profile/pb_profile.c -o "$OUT/config_plain" $LF
"$OUT/config_plain"
ASAN_OPTIONS=detect_leaks=1 "$OUT/config_test"
ASAN_OPTIONS=detect_leaks=1 "$OUT/json_test"
ASAN_OPTIONS=detect_leaks=1 "$OUT/boot_test"
ASAN_OPTIONS=detect_leaks=1 "$OUT/list_test"
gcc -O2 -Wall -Wextra -I. tests/events_test.c gui_events.c -o "$OUT/events_plain" -pthread
time "$OUT/events_plain"
gcc -g -Wall -Wextra -fsanitize=address,undefined -I. tests/events_test.c gui_events.c -o "$OUT/events_asan" -pthread
ASAN_OPTIONS=detect_leaks=1 "$OUT/events_asan"
# TSan needs ASLR switched off (setarch -R), which some containers forbid
if setarch "$(uname -m)" -R true 2>/dev/null; then
    gcc -g -O1 -Wall -Wextra -fsanitize=thread -I. tests/events_test.c gui_events.c -o "$OUT/events_tsan" -pthread
    setarch "$(uname -m)" -R "$OUT/events_tsan"
else
    echo "skipping the ThreadSanitizer run: setarch -R is not permitted here"
fi

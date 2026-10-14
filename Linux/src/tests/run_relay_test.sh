#!/bin/sh
# Builds and runs the root-free relay test (loopback only). Usage: run_relay_test.sh [plain|asan|both]  (default both)
set -e
cd "$(dirname "$0")"
mode="${1:-both}"
out="${TMPDIR:-/tmp}"
CF="-std=gnu11 -Wall -Wextra -O1 -g -D_GNU_SOURCE -fstack-protector-strong -I.. "
if [ "$mode" = plain ] || [ "$mode" = both ]; then
    gcc $CF -O2 relay_test.c ../pb_relay.c -o "$out/relay_test" -lpthread
    "$out/relay_test"
fi
if [ "$mode" = asan ] || [ "$mode" = both ]; then
    gcc $CF -fsanitize=address,undefined -fno-omit-frame-pointer relay_test.c ../pb_relay.c -o "$out/relay_test_asan" -lpthread
    PB_TEST_WATCHDOG="${PB_TEST_WATCHDOG:-900}" LARGE_MB="${LARGE_MB:-4}" THRU_MB="${THRU_MB:-32}" ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$out/relay_test_asan"
fi

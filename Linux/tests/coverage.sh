#!/bin/bash
# Line coverage of the library, CLI, profile reader and GUI under the whole test suite (end-to-end suites + unit tests).
#   sudo Linux/tests/coverage.sh               build instrumented copies, run everything, print the table
#   COV_MIN=88 sudo Linux/tests/coverage.sh    also exit 1 if the library's line coverage is below 88 %
#   Linux/tests/coverage.sh unit               only the root-free unit tests (no root, no kernel)
#   Linux/tests/coverage.sh report             only print the table for the data already collected
# Everything lives in $COV_DIR (default /tmp/pb-coverage), the list of lines nobody executed is in $COV_DIR/uncovered.txt.
# The eBPF program runs in the kernel and cannot be measured; its behaviour is covered by the end-to-end suites.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
COV_DIR="${COV_DIR:-/tmp/pb-coverage}"
BUILD="$COV_DIR/build"; OUT="$COV_DIR/out"; UNIT="$COV_DIR/unit"
BPFTOOL="${BPFTOOL:-bpftool}"; export BPFTOOL

report() {
    python3 -I "$HERE/coverage_report.py" --uncovered "$COV_DIR/uncovered.txt" ${COV_MIN:+--min-library "$COV_MIN"} "$COV_DIR"
}

unit_tests() {
    rm -rf "$UNIT"; mkdir -p "$UNIT"
    local cf="--coverage -O0 -g -D_GNU_SOURCE -std=gnu11 -w"
    local gtk; gtk="$(pkg-config --cflags --libs gtk+-3.0 2> /dev/null)"
    echo "== unit tests (instrumented)"
    ( cd "$ROOT/src" &&
      gcc $cf tests/rules_test.c pb_rules.c -o "$UNIT/rules_test" && "$UNIT/rules_test" &&
      gcc $cf tests/dns_test.c pb_dns.c -o "$UNIT/dns_test" && "$UNIT/dns_test" &&
      gcc $cf tests/proc_test.c pb_proc.c -o "$UNIT/proc_test" && "$UNIT/proc_test" &&
      gcc $cf -I. tests/relay_test.c pb_relay.c -o "$UNIT/relay_test" -lpthread && PB_CHURN_TCP=2000 PB_CHURN_UDP=500 PB_PERF_UDP=2000 PB_PERF_CONNS=100 "$UNIT/relay_test" ) 2>&1 | grep -E "FAIL|passed|RESULT" || true
    ( cd "$ROOT/profile/tests" && gcc $cf profile_test.c ../pb_profile.c -o "$UNIT/profile_test" && "$UNIT/profile_test" ) 2>&1 | tail -1
    if [ -n "$gtk" ]; then
        ( cd "$ROOT/gui" &&
          gcc $cf -I../src -I../profile -I. tests/config_test.c gui_config.c ../profile/pb_profile.c -o "$UNIT/config_test" $gtk && "$UNIT/config_test" &&
          gcc $cf -I../src -I. tests/json_test.c gui_json.c -o "$UNIT/json_test" $gtk && "$UNIT/json_test" &&
          gcc $cf -I. $(pkg-config --cflags glib-2.0) -DPB_TEST_HOOKS -I../src tests/boot_test.c gui_boot.c ../src/pb_unit.c -o "$UNIT/boot_test" $(pkg-config --libs glib-2.0) && "$UNIT/boot_test" &&
          gcc $cf -I. tests/events_test.c gui_events.c -o "$UNIT/events_test" -pthread && "$UNIT/events_test" ) 2>&1 | grep -E "FAIL|passed" || true
    fi
}

case "${1:-}" in
    report) report; exit $? ;;
    unit)   unit_tests; echo; report; exit $? ;;
esac
[ "$(id -u)" = 0 ] || { echo "run as root (or use: coverage.sh unit)"; exit 1; }

rm -rf "$COV_DIR"; mkdir -p "$COV_DIR"
PB_BUILD_DIR="$BUILD" AUDIT=0 OUTPUT_DIR="$OUT" EXTRA_CFLAGS="--coverage -O0 -g" EXTRA_LDFLAGS="--coverage" LTO=0 STRIP_FLAG= OPT=-O0 \
    "$ROOT/build.sh" > "$COV_DIR/build.log" 2>&1 || { tail -20 "$COV_DIR/build.log"; exit 1; }

export PB_DIR="$OUT"
for t in e2e e2e_rules e2e_domains e2e_security e2e_profile e2e_parity e2e_faults e2e_udp e2e_rules_diff e2e_logging e2e_checker e2e_cli e2e_exempt e2e_lifecycle api_live e2e_openssh e2e_daemon; do
    [ -f "$HERE/$t.sh" ] || continue
    echo "== $t"
    timeout 900 bash "$HERE/$t.sh" 2>&1 | grep -E "FAIL|passed=|RESULT" || true
done
echo "== churn"; timeout 900 bash "$HERE/churn.sh" 1500 2>&1 | grep -E "PASS|FAIL" || echo "FAIL churn produced no result (timed out?)"
if [ -x "$OUT/ProxyBridgeGUI" ] && command -v broadwayd > /dev/null; then
    echo "== gui_headless"; timeout 300 bash "$HERE/gui_headless.sh" "$OUT/ProxyBridgeGUI" "$OUT" 2>&1 | grep -E "FAIL|passed=" || true
fi
if command -v broadwayd > /dev/null; then
    echo "== gui_ui"
    UI_BUILD_DIR="$COV_DIR/uibuild" EXTRA_CFLAGS="--coverage -O0" EXTRA_LDFLAGS="--coverage" timeout 600 bash "$HERE/gui_ui.sh" "$OUT" 2>&1 | grep -E "FAIL|checks" || true
fi
unit_tests
echo
report

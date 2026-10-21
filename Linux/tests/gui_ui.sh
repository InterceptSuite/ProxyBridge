#!/bin/bash
# Drives the real GUI's windows and dialogs (gui/tests/ui_test.c) under the GTK Broadway backend. Needs root, broadwayd, python3.
#   sudo Linux/tests/gui_ui.sh [libdir]       libdir: directory with libproxybridge.so (default Linux/output)
# The test binary is compiled here from the GUI sources (main.c as pb_gui_main) in a temporary directory.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
LIBDIR="${1:-${PB_DIR:-$ROOT/output}}"
[ -f "$LIBDIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or pass the directory with libproxybridge.so"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"
BUILD="${UI_BUILD_DIR:-$WORK}"          # coverage runs keep the objects (and their .gcno files) here
mkdir -p "$BUILD"
cleanup() { kill $FAKE $BW $DAEMON 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
DAEMON=
trap cleanup EXIT

G="$ROOT/gui"
SRC=$(ls "$G"/*.c | grep -v "/main.c$")
gcc -O1 -g -w -D_GNU_SOURCE ${EXTRA_CFLAGS:-} -I"$ROOT/src" -I"$ROOT/profile" -I"$G" $(pkg-config --cflags gtk+-3.0) \
    -DPB_TEST_HOOKS -Dmain=pb_gui_main -c "$G/main.c" -o "$BUILD/gui_main.o" || exit 1
gcc -O1 -g -w -D_GNU_SOURCE -DPB_TEST_HOOKS ${EXTRA_CFLAGS:-} -I"$ROOT/src" -I"$ROOT/profile" -I"$G" $(pkg-config --cflags gtk+-3.0) \
    -o "$BUILD/ui_test" "$G/tests/ui_test.c" "$BUILD/gui_main.o" $SRC "$ROOT/profile/pb_profile.c" "$ROOT/src/pb_ipc.c" "$ROOT/src/pb_unit.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lproxybridge -lpthread $(pkg-config --libs gtk+-3.0) ${EXTRA_LDFLAGS:-} || exit 1

python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & FAKE=$!
BW=
run_ui() {   # $1 = label; the environment says whether the window talks to a service
    echo "== window: $1"
    # A display server of its own for every run: broadwayd aborts when its client disappears, so one cannot serve two runs.
    # (no core dump: apport would pop up a crash report for that abort)
    ( ulimit -c 0; exec broadwayd :8 ) > /dev/null 2>&1 & BW=$!
    sleep 1.5
    GDK_BACKEND=broadway BROADWAY_DISPLAY=:8 LD_LIBRARY_PATH="$LIBDIR" \
        timeout 300 "$BUILD/ui_test" 2>&1 | grep -v "^$\|Gtk-WARNING\|GLib-GIO\|dconf"
    local rc="${PIPESTATUS[0]}"
    kill $BW 2>/dev/null; wait $BW 2>/dev/null; BW=
    sleep 0.5
    return "$rc"
}

rc=0
if [ "${UI_MODES:-both}" != service ]; then
    mkdir -p "$WORK/cfg"
    # PROXYBRIDGE_SOCKET points at nothing: a service installed on this machine must not be used (or changed) by this run
    mkdir -p "$WORK/units"
    PROXYBRIDGE_SYSTEMD_DIR="$WORK/units" PROXYBRIDGE_SOCKET="$WORK/no-service.sock" PROXYBRIDGE_CONFIG_DIR="$WORK/cfg" run_ui "its own engine (root, no service)" || rc=1
fi
if [ "${UI_MODES:-both}" != embedded ] && [ -x "$LIBDIR/ProxyBridge" ]; then
    # the same suite, every engine and profile call going over the socket to a ProxyBridge --daemon
    mkdir -p "$WORK/cfg2" "$WORK/run"
    chmod 755 "$WORK" "$WORK/run"
    PROXYBRIDGE_CONFIG_DIR="$WORK/cfg2" LD_LIBRARY_PATH="$LIBDIR" \
        "$LIBDIR/ProxyBridge" --daemon --socket "$WORK/run/ctl.sock" --verbose 1 > "$WORK/daemon.log" 2>&1 & DAEMON=$!
    for _ in $(seq 40); do [ -S "$WORK/run/ctl.sock" ] && break; sleep 0.25; done
    PROXYBRIDGE_CONFIG_DIR="$WORK/cfg2" PROXYBRIDGE_SOCKET="$WORK/run/ctl.sock" \
        run_ui "through the service" || rc=1
    kill "$DAEMON" 2>/dev/null; wait "$DAEMON" 2>/dev/null
fi
exit $rc

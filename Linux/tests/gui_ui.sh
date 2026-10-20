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
cleanup() { kill $FAKE $BW 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

G="$ROOT/gui"
SRC=$(ls "$G"/*.c | grep -v "/main.c$")
gcc -O1 -g -w -D_GNU_SOURCE ${EXTRA_CFLAGS:-} -I"$ROOT/src" -I"$ROOT/profile" -I"$G" $(pkg-config --cflags gtk+-3.0) \
    -DPB_TEST_HOOKS -Dmain=pb_gui_main -c "$G/main.c" -o "$BUILD/gui_main.o" || exit 1
gcc -O1 -g -w -D_GNU_SOURCE -DPB_TEST_HOOKS ${EXTRA_CFLAGS:-} -I"$ROOT/src" -I"$ROOT/profile" -I"$G" $(pkg-config --cflags gtk+-3.0) \
    -o "$BUILD/ui_test" "$G/tests/ui_test.c" "$BUILD/gui_main.o" $SRC "$ROOT/profile/pb_profile.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lproxybridge -lpthread $(pkg-config --libs gtk+-3.0) ${EXTRA_LDFLAGS:-} || exit 1

python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & FAKE=$!
broadwayd :8 > /dev/null 2>&1 & BW=$!
sleep 1.5
mkdir -p "$WORK/cfg"
GDK_BACKEND=broadway BROADWAY_DISPLAY=:8 PROXYBRIDGE_CONFIG_DIR="$WORK/cfg" LD_LIBRARY_PATH="$LIBDIR" \
    timeout 300 "$BUILD/ui_test" 2>&1 | grep -v "^$\|Gtk-WARNING\|GLib-GIO\|dconf"
exit "${PIPESTATUS[0]}"

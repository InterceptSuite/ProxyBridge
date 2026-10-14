#!/bin/bash
# Builds libproxybridge.so, the CLI and (if GTK3 is present) the GUI.
# Everything is compiled in a temporary directory; only the final binaries are copied to output/,
# so the source tree never collects .o files, generated headers or libraries.
#
#   ./build.sh                    -> Linux/output/
#   OUTPUT_DIR=/some/dir ./build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/proxybridge-build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

need() {  # command, install hint
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found. $2"; exit 1; }
}
need gcc     "Install: sudo apt install build-essential | sudo dnf install gcc"
need make    "Install: sudo apt install make | sudo dnf install make"
need clang   "Needed to compile the eBPF program. Install: sudo apt install clang | sudo dnf install clang"
need bpftool "Needed to generate the eBPF skeleton. Install: sudo apt install bpftool | sudo dnf install bpftool"
if [ ! -f /usr/include/bpf/libbpf.h ] && ! pkg-config --exists libbpf 2>/dev/null; then
    echo "ERROR: libbpf development files not found. Install: sudo apt install libbpf-dev | sudo dnf install libbpf-devel"
    exit 1
fi

# Fresh output directory
if [ -e "$OUTPUT_DIR" ]; then
    echo "Removing existing output directory..."
    rm -rf "$OUTPUT_DIR" 2>/dev/null || {
        echo "ERROR: cannot remove $OUTPUT_DIR (files owned by another user, e.g. root)."
        echo "       Remove it manually (sudo rm -rf '$OUTPUT_DIR') or choose another one with OUTPUT_DIR=..."
        exit 1
    }
fi
mkdir -p "$OUTPUT_DIR"
echo ""

# Library
echo "=== Building Library ==="
make -C "$SCRIPT_DIR/src" BUILD_DIR="$BUILD_DIR/lib"
[ -f "$BUILD_DIR/lib/libproxybridge.so" ] || { echo "Library build failed!"; exit 1; }
echo "Library build successful"
echo ""

# CLI
echo "=== Building CLI ==="
make -C "$SCRIPT_DIR/cli" BUILD_DIR="$BUILD_DIR/cli" LIBDIR="$BUILD_DIR/lib"
[ -f "$BUILD_DIR/cli/ProxyBridge" ] || { echo "CLI build failed!"; exit 1; }
echo "CLI build successful"
echo ""

# GUI (optional)
echo "=== Building GUI ==="
GUI_BUILT=0
if pkg-config --exists gtk+-3.0; then
    mkdir -p "$BUILD_DIR/gui"
    GUI_CFLAGS=(-Wall -Wno-unused-parameter -O3 "-I$SCRIPT_DIR/src" -D_GNU_SOURCE -fstack-protector-strong
                -D_FORTIFY_SOURCE=2 -fPIE -Wformat -Wformat-security -Werror=format-security -fno-strict-overflow
                -fno-delete-null-pointer-checks -fwrapv $(pkg-config --cflags gtk+-3.0))
    GUI_OBJS=()
    for src in "$SCRIPT_DIR"/gui/*.c; do
        obj="$BUILD_DIR/gui/$(basename "${src%.c}").o"
        gcc "${GUI_CFLAGS[@]}" -c "$src" -o "$obj"
        GUI_OBJS+=("$obj")
    done
    gcc -o "$BUILD_DIR/gui/ProxyBridgeGUI" "${GUI_OBJS[@]}" -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -s \
        "-L$BUILD_DIR/lib" -Wl,-rpath,'$ORIGIN' -lproxybridge -lpthread $(pkg-config --libs gtk+-3.0) -export-dynamic
    GUI_BUILT=1
    echo "GUI build successful"
else
    echo "GTK3 not found. Skipping GUI build."
    echo "  Install with: sudo apt install libgtk-3-dev  (Debian/Ubuntu/Mint)"
    echo "                sudo dnf install gtk3-devel    (Fedora)"
fi
echo ""

# Only the final files go to output/
echo "Copying binaries to $OUTPUT_DIR ..."
cp "$BUILD_DIR/lib/libproxybridge.so" "$OUTPUT_DIR/"
cp "$BUILD_DIR/cli/ProxyBridge" "$OUTPUT_DIR/"
[ "$GUI_BUILT" = 1 ] && cp "$BUILD_DIR/gui/ProxyBridgeGUI" "$OUTPUT_DIR/"
echo ""

echo "==================================="
echo "Build Complete!"
echo "==================================="
ls -lh "$OUTPUT_DIR"
echo ""
echo "Output location: $OUTPUT_DIR"

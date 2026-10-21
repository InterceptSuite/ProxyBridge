#!/bin/bash
# Builds libproxybridge.so, the CLI and (if GTK3 is present) the GUI.
# Everything is compiled in a temporary directory; only the final binaries are copied to output/, after an audit of their
# portability (glibc floor) and hardening.
#
#   ./build.sh                       -> Linux/output/
#   OUTPUT_DIR=/some/dir ./build.sh
#   WERROR=1 ./build.sh              warnings are errors (CI)     LTO=0 ./build.sh   no link-time optimisation
#   AUDIT=0 ./build.sh               skip the binary audit      STATIC_LIBBPF=0 ./build.sh   use the system libbpf
#   PB_BUILD_DIR=/dir ./build.sh     keep the intermediate files there (used by tests/coverage.sh)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"
if [ -n "${PB_BUILD_DIR:-}" ]; then      # keep the intermediate files (coverage builds need the .gcno files)
    BUILD_DIR="$PB_BUILD_DIR"; mkdir -p "$BUILD_DIR"
else
    BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/proxybridge-build.XXXXXX")"
    trap 'rm -rf "$BUILD_DIR"' EXIT
fi
JOBS="$(nproc 2>/dev/null || echo 2)"
export WERROR LTO OPT

need() {  # command, install hint
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found. $2"; exit 1; }
}
need gcc     "Install: sudo apt install build-essential | sudo dnf install gcc"
need curl    "Needed to fetch the pinned libbpf, libelf and zlib sources. Install: sudo apt install curl"
need make    "Install: sudo apt install make | sudo dnf install make"
need clang   "Needed to compile the eBPF program. Install: sudo apt install clang | sudo dnf install clang"
BPFTOOL="${BPFTOOL:-bpftool}"   # set BPFTOOL=/path/to/bpftool if it is not on PATH (e.g. /usr/lib/linux-tools/*/bpftool on Ubuntu)
export BPFTOOL
need "$BPFTOOL" "Needed to generate the eBPF skeleton. Install: sudo apt install linux-tools-generic (Ubuntu) | sudo apt install bpftool (Debian) | sudo dnf install bpftool"
if [ "${STATIC_LIBBPF:-1}" != 1 ] && [ ! -f /usr/include/bpf/libbpf.h ] && ! pkg-config --exists libbpf 2>/dev/null; then
    echo "ERROR: libbpf development files not found. Install: sudo apt install libbpf-dev | sudo dnf install libbpf-devel"
    exit 1
fi
if [ "${STATIC_LIBBPF:-1}" = 1 ]; then
    # libbpf, libelf and zlib are downloaded (checksum-verified) and built once into ~/.cache/proxybridge, then linked statically
    need curl "Needed to download the pinned libbpf, libelf and zlib sources."
    need bzip2 "Needed to unpack elfutils. Install: sudo apt install bzip2 | sudo dnf install bzip2"
    need make "Needed to build."
fi

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

echo "=== Building Library ==="
LIBBPF_ARGS=()
if [ "${STATIC_LIBBPF:-1}" = 1 ]; then
    if make -s -C "$SCRIPT_DIR/src" libbpf-static; then
        LIBBPF_ARGS=(LIBBPF_DIR="$(make -s -C "$SCRIPT_DIR/src" libbpf-path)")
        echo "libbpf: linking the pinned static build"
    else
        echo "WARNING: could not build the pinned libbpf (needs network, curl, libelf-dev and zlib1g-dev);"
        echo "         falling back to the system libbpf. The result will not run on systems without libbpf >= 1.0."
        export ALLOW_DYNAMIC_LIBBPF=1
    fi
else
    export ALLOW_DYNAMIC_LIBBPF=1
fi
make -j"$JOBS" -C "$SCRIPT_DIR/src" BUILD_DIR="$BUILD_DIR/lib" "${LIBBPF_ARGS[@]}"
[ -f "$BUILD_DIR/lib/libproxybridge.so" ] || { echo "Library build failed!"; exit 1; }
echo "Library build successful"
echo ""

echo "=== Building CLI ==="
make -j"$JOBS" -C "$SCRIPT_DIR/cli" BUILD_DIR="$BUILD_DIR/cli" LIBDIR="$BUILD_DIR/lib" "${LIBBPF_ARGS[@]}"
[ -f "$BUILD_DIR/cli/ProxyBridge" ] || { echo "CLI build failed!"; exit 1; }
echo "CLI build successful"
echo ""

echo "=== Building GUI ==="
GUI_BUILT=0
if pkg-config --exists gtk+-3.0; then
    make -j"$JOBS" -C "$SCRIPT_DIR/gui" BUILD_DIR="$BUILD_DIR/gui" LIBDIR="$BUILD_DIR/lib"
    GUI_BUILT=1
    echo "GUI build successful"
else
    echo "GTK3 not found. Skipping GUI build."
    echo "  Install with: sudo apt install libgtk-3-dev  (Debian/Ubuntu/Mint)"
    echo "                sudo dnf install gtk3-devel    (Fedora)"
fi
echo ""

echo "Copying binaries to $OUTPUT_DIR ..."
cp "$BUILD_DIR/lib/libproxybridge.so" "$OUTPUT_DIR/"
cp "$BUILD_DIR/cli/ProxyBridge" "$OUTPUT_DIR/"
[ "$GUI_BUILT" = 1 ] && cp "$BUILD_DIR/gui/ProxyBridgeGUI" "$OUTPUT_DIR/"
install -m 755 "$SCRIPT_DIR/setup.sh" "$OUTPUT_DIR/setup.sh"
if [ "$GUI_BUILT" = 1 ]; then      # launcher entry and icon: the desktop shows the logo and name for the running window
    install -m 644 "$SCRIPT_DIR/gui/proxybridge.desktop" "$OUTPUT_DIR/proxybridge.desktop"
    install -m 644 "$SCRIPT_DIR/gui/icons/proxybridge-128.png" "$SCRIPT_DIR/gui/icons/proxybridge-256.png" "$OUTPUT_DIR/"
fi
echo ""

if [ "${AUDIT:-1}" = 1 ]; then
    echo "=== Auditing binaries ==="
    "$SCRIPT_DIR/tests/check_binaries.sh" "$OUTPUT_DIR" || { echo "Audit failed: the binaries are not portable/hardened enough to ship."; exit 1; }
    echo ""
fi

echo "==================================="
echo "Build Complete!"
echo "==================================="
ls -lh "$OUTPUT_DIR"
echo ""
echo "Output location: $OUTPUT_DIR"

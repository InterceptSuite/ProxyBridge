#!/bin/bash
# Builds Vendor/HevSocks5Tunnel.xcframework (iOS device and simulator) from a pinned hev-socks5-tunnel commit.
# Needs full Xcode:  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

COMMIT=4702e9ad2815f3a04e2af63b2e7eb36e861c9c86
SRC=hev-socks5-tunnel
OUT=HevSocks5Tunnel.xcframework
MIN_IOS=16.0

if [ ! -d "$SRC" ]; then
    git clone https://github.com/heiher/hev-socks5-tunnel "$SRC"
fi
git -C "$SRC" fetch --quiet origin
git -C "$SRC" checkout --quiet "$COMMIT"
git -C "$SRC" submodule update --init --recursive --quiet

rm -rf build "$OUT"

# build_slice <sdk> <arch> <version flag> <output dir>
build_slice() {
    local sdk=$1 arch=$2 flag=$3 dir=build/$4
    local clang="xcrun --sdk $sdk --toolchain $sdk clang"
    make -C "$SRC" clean >/dev/null 2>&1 || true
    make -C "$SRC" PP="$clang" CC="$clang" CFLAGS="-arch $arch $flag" LFLAGS="-arch $arch $flag" static
    mkdir -p "$dir"
    libtool -static -o "$dir/libhev-socks5-tunnel.a" \
        "$SRC/bin/libhev-socks5-tunnel.a" \
        "$SRC/third-part/lwip/bin/liblwip.a" \
        "$SRC/third-part/yaml/bin/libyaml.a" \
        "$SRC/third-part/hev-task-system/bin/libhev-task-system.a"
}

build_slice iphoneos arm64 "-miphoneos-version-min=$MIN_IOS" device
build_slice iphonesimulator arm64 "-mios-simulator-version-min=$MIN_IOS" sim-arm64
build_slice iphonesimulator x86_64 "-mios-simulator-version-min=$MIN_IOS" sim-x86_64
make -C "$SRC" clean >/dev/null 2>&1 || true

mkdir -p build/sim
lipo -create build/sim-arm64/libhev-socks5-tunnel.a build/sim-x86_64/libhev-socks5-tunnel.a \
    -output build/sim/libhev-socks5-tunnel.a

mkdir -p build/include/HevSocks5Tunnel
cp "$SRC/src/hev-main.h" "$SRC/module.modulemap" build/include/HevSocks5Tunnel/

xcodebuild -create-xcframework \
    -library build/device/libhev-socks5-tunnel.a -headers build/include \
    -library build/sim/libhev-socks5-tunnel.a -headers build/include \
    -output "$OUT"

rm -rf build
echo "Built $OUT"

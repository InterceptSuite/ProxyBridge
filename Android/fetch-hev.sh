#!/bin/bash
# Fetches hev-socks5-tunnel at a pinned commit into app/src/main/jni, where the Android build compiles it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

COMMIT=4702e9ad2815f3a04e2af63b2e7eb36e861c9c86
DEST=app/src/main/jni/hev-socks5-tunnel

if [ ! -d "$DEST" ]; then
    git clone https://github.com/heiher/hev-socks5-tunnel "$DEST"
fi
git -C "$DEST" fetch --quiet origin
git -C "$DEST" checkout --quiet "$COMMIT"
git -C "$DEST" submodule update --init --recursive --quiet
echo "hev-socks5-tunnel is at $COMMIT"

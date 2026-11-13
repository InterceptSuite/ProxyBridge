#!/bin/bash
# Downloads the latest ProxyBridge release for Linux, checks it, and installs it with the setup.sh that is inside the archive:
#   curl -Lo deploy.sh https://raw.githubusercontent.com/InterceptSuite/ProxyBridge/refs/heads/master/Linux/deploy.sh && sudo bash deploy.sh
# Everything that is installed (programs, the ProxyBridge service, the group) is done by setup.sh, so there is one installer.
# It picks the archive for this machine: ProxyBridge-Linux-v*.tar.gz on x86_64, ProxyBridge-Linux-arm64-v*.tar.gz on aarch64.
#   PB_ALLOW_UNVERIFIED=1   install a release whose archive has no SHA-256 digest in the GitHub API (nothing else is skipped)
set -euo pipefail

GITHUB_REPO="InterceptSuite/ProxyBridge"
GITHUB_API="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
DOWNLOAD_PREFIX="https://github.com/$GITHUB_REPO/releases/download/"

echo ""
echo "==================================="
echo "ProxyBridge Auto-Deploy Script"
echo "==================================="
echo ""

# Test hook (tests/deploy_select_test.sh): PB_SELECT_ONLY=1 prints the archive chosen from a saved API answer and installs nothing.
SELECT_ONLY="${PB_SELECT_ONLY:-0}"

if [ "$SELECT_ONLY" != 1 ] && [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    echo "Please run: sudo bash deploy.sh"
    exit 1
fi

case "${PB_ARCH:-$(uname -m)}" in
    x86_64|amd64)  ASSET_RE='^ProxyBridge-Linux-v[0-9].*\.tar\.gz$' ;;
    aarch64|arm64) ASSET_RE='^ProxyBridge-Linux-arm64-v[0-9].*\.tar\.gz$' ;;
    *) echo "ERROR: ProxyBridge for Linux is built for x86_64 and arm64 (aarch64); this machine is $(uname -m)"; exit 1 ;;
esac
export ASSET_RE

missing=()
for tool in curl tar sha256sum mktemp; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "ERROR: missing required tools: ${missing[*]}"
    echo "  Debian/Ubuntu: sudo apt install curl tar coreutils"
    echo "  Fedora:        sudo dnf install curl tar coreutils"
    echo "  Arch:          sudo pacman -S curl tar coreutils"
    exit 1
fi

# A directory only root can use, with a name nobody can predict: nothing in it can be swapped by another user between the download and
# the moment it is installed (a fixed name under /tmp could be created in advance by any local user).
WORK="$(mktemp -d /var/tmp/proxybridge-install.XXXXXX)"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
umask 077
fetch() { curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 "$@"; }

echo "Fetching latest release information..."
if [ "$SELECT_ONLY" = 1 ] && [ -n "${PB_API_JSON:-}" ]; then
    api_response="$(cat "$PB_API_JSON")"
else
    api_response="$(fetch "$GITHUB_API")" || { echo "ERROR: Failed to fetch release information from GitHub"; exit 1; }
fi

expected=""
if command -v jq >/dev/null 2>&1; then
    expected="$(printf '%s' "$api_response" | jq -r --arg re "$ASSET_RE" '.assets[] | select(.name | test($re)) | .digest // empty' | head -1)"
    download_url="$(printf '%s' "$api_response" | jq -r --arg re "$ASSET_RE" '.assets[] | select(.name | test($re)) | .browser_download_url' | head -1)"
else
    # the API lists "digest" before "browser_download_url" inside each asset
    expected="$(printf '%s\n' "$api_response" | awk '/"digest":/ { d=$0 } /"browser_download_url":/ { n=$0; sub(/"[ ]*,?[ ]*$/, "", n); sub(/.*\//, "", n); if (n ~ ENVIRON["ASSET_RE"]) { print d; exit } }' | sed -n 's/.*"digest": *"\([^"]*\)".*/\1/p')"
    download_url="$(printf '%s\n' "$api_response" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"/\1/' | awk '{ n=$0; sub(/.*\//, "", n); if (n ~ ENVIRON["ASSET_RE"]) { print; exit } }')"
fi
if [ -z "$download_url" ] || [ "${download_url#"$DOWNLOAD_PREFIX"}" = "$download_url" ]; then
    echo "ERROR: Could not find the Linux release archive in the latest release"
    echo "Please check if a Linux release is available at: https://github.com/$GITHUB_REPO/releases/latest"
    exit 1
fi
if [ "$SELECT_ONLY" = 1 ]; then echo "url=$download_url"; echo "digest=$expected"; exit 0; fi
filename="$(basename "$download_url")"
case "$filename" in
    *[!A-Za-z0-9._-]*|"") echo "ERROR: unexpected file name in the release"; exit 1 ;;
esac
echo "Found release: $filename"

echo ""
echo "Downloading $filename..."
fetch -o "$WORK/$filename" "$download_url" || { echo "ERROR: Failed to download the release archive"; exit 1; }

echo "Checking the download..."
expected="${expected#sha256:}"
if [ -n "$expected" ]; then
    actual="$(sha256sum "$WORK/$filename" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        echo "ERROR: the checksum of the download does not match the one GitHub reports for the release. Nothing was installed."
        exit 1
    fi
    echo "  SHA-256 matches"
elif [ "${PB_ALLOW_UNVERIFIED:-0}" = 1 ]; then
    echo "WARNING: GitHub reports no SHA-256 digest for this release; installing without checking it (PB_ALLOW_UNVERIFIED=1)"
else
    echo "ERROR: GitHub reports no SHA-256 digest for this release to check the download against."
    echo "       Verify the archive yourself and run again with PB_ALLOW_UNVERIFIED=1, or install from the downloaded archive by hand."
    exit 1
fi

echo ""
echo "Extracting..."
if tar -tzf "$WORK/$filename" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
    echo "ERROR: the archive contains absolute paths or '..'; refusing to extract it"
    exit 1
fi
mkdir "$WORK/pkg"
tar -xzf "$WORK/$filename" -C "$WORK/pkg" --no-same-owner --no-same-permissions
[ -f "$WORK/pkg/setup.sh" ] || { echo "ERROR: setup.sh is not in the archive"; exit 1; }

echo ""
umask 022
cd "$WORK/pkg"
bash ./setup.sh

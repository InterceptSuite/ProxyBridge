#!/bin/bash
# Downloads the latest ProxyBridge release for Linux, checks it, and installs it with the setup.sh that is inside the archive:
#   curl -Lo deploy.sh https://raw.githubusercontent.com/InterceptSuite/ProxyBridge/refs/heads/master/Linux/deploy.sh && sudo bash deploy.sh
# Everything that is installed (programs, the ProxyBridge service, the group) is done by setup.sh, so there is one installer.
#   PB_ALLOW_UNVERIFIED=1   install a release that has no .sha256 file next to the archive (nothing else is skipped)
set -euo pipefail

GITHUB_REPO="InterceptSuite/ProxyBridge"
GITHUB_API="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
DOWNLOAD_PREFIX="https://github.com/$GITHUB_REPO/releases/download/"

echo ""
echo "==================================="
echo "ProxyBridge Auto-Deploy Script"
echo "==================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    echo "Please run: sudo bash deploy.sh"
    exit 1
fi

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
api_response="$(fetch "$GITHUB_API")" || { echo "ERROR: Failed to fetch release information from GitHub"; exit 1; }

if command -v jq >/dev/null 2>&1; then
    download_url="$(printf '%s' "$api_response" | jq -r '.assets[] | select(.name | test("^ProxyBridge-Linux-.*\\.tar\\.gz$")) | .browser_download_url' | head -1)"
else
    download_url="$(printf '%s' "$api_response" | grep -o '"browser_download_url": *"[^"]*ProxyBridge-Linux-[^"/]*\.tar\.gz"' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')"
fi
if [ -z "$download_url" ] || [ "${download_url#"$DOWNLOAD_PREFIX"}" = "$download_url" ]; then
    echo "ERROR: Could not find the Linux release archive in the latest release"
    echo "Please check if a Linux release is available at: https://github.com/$GITHUB_REPO/releases/latest"
    exit 1
fi
filename="$(basename "$download_url")"
case "$filename" in
    *[!A-Za-z0-9._-]*|"") echo "ERROR: unexpected file name in the release"; exit 1 ;;
esac
echo "Found release: $filename"

echo ""
echo "Downloading $filename..."
fetch -o "$WORK/$filename" "$download_url" || { echo "ERROR: Failed to download the release archive"; exit 1; }

echo "Checking the download..."
if fetch -o "$WORK/$filename.sha256" "$download_url.sha256" 2>/dev/null; then
    expected="$(awk '{print $1; exit}' "$WORK/$filename.sha256")"
    actual="$(sha256sum "$WORK/$filename" | awk '{print $1}')"
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
        echo "ERROR: the checksum of the download does not match ($filename.sha256). Nothing was installed."
        exit 1
    fi
    echo "  SHA-256 matches"
elif [ "${PB_ALLOW_UNVERIFIED:-0}" = 1 ]; then
    echo "WARNING: this release has no .sha256 file; installing without checking it (PB_ALLOW_UNVERIFIED=1)"
else
    echo "ERROR: this release has no .sha256 file to check the download against."
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

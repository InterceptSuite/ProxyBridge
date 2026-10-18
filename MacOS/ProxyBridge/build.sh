#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="4.1.0"

# the pkg name/version here and the version shown in the app (About page, bundle)
# come from different places, make a mismatch fail the build instead of shipping it
PROJECT_VERSIONS=$(grep "MARKETING_VERSION" "$SCRIPT_DIR/ProxyBridge.xcodeproj/project.pbxproj" | sed -E 's/.*= *([^;]+);.*/\1/' | sort -u)
if [ "$PROJECT_VERSIONS" != "$VERSION" ]; then
    echo "Version mismatch: build.sh VERSION=$VERSION but MARKETING_VERSION in the Xcode project is: $(echo $PROJECT_VERSIONS)"
    exit 1
fi

if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

APP_PATH="$SCRIPT_DIR/output/ProxyBridge.app"

if [ ! -d "$APP_PATH" ]; then
    echo "Error: ProxyBridge.app not found in output directory"
    echo "Export the app from Xcode to output/ first"
    exit 1
fi

verify_universal() {
    local binary="$1"
    local archs
    archs="$(lipo -archs "$binary" 2>/dev/null || echo "")"
    if [[ "$archs" != *"arm64"* || "$archs" != *"x86_64"* ]]; then
        echo "Error: $binary is not universal (found: ${archs:-none})"
        echo "Build with ARCHS=\"arm64 x86_64\" ONLY_ACTIVE_ARCH=NO before packaging."
        exit 1
    fi
    echo "  universal ok: $binary ($archs)"
}

verify_universal "$APP_PATH/Contents/MacOS/ProxyBridge"
EXT_BIN="$APP_PATH/Contents/Library/SystemExtensions/com.interceptsuite.ProxyBridge.extension.systemextension/Contents/MacOS/com.interceptsuite.ProxyBridge.extension"
if [ -f "$EXT_BIN" ]; then
    verify_universal "$EXT_BIN"
fi

mkdir -p "$SCRIPT_DIR/build/component"

cp -R "$APP_PATH" "$SCRIPT_DIR/build/component/"

# strip AppleDouble junk so it never lands in the payload
dot_clean "$SCRIPT_DIR/build/component" 2>/dev/null || true
find "$SCRIPT_DIR/build/component" -name '._*' -delete 2>/dev/null || true

echo "Creating installer package..."

# force BundleIsRelocatable=false so the app always installs to /Applications.
# otherwise macOS relocates the install onto any existing copy of the app it
# finds on disk (bundle relocation), leaving /Applications empty.
pkgbuild --analyze --root build/component build/component.plist
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" build/component.plist

# scripts/postinstall installs the `proxybridge` command (a launcher for the app's own executable).
# an installer script that is not executable is skipped silently, so check it here
[ -x "$SCRIPT_DIR/scripts/postinstall" ] || { echo "ERROR: scripts/postinstall is not executable (chmod +x)"; exit 1; }
pkgbuild \
    --root build/component \
    --component-plist build/component.plist \
    --scripts "$SCRIPT_DIR/scripts" \
    --identifier com.interceptsuite.ProxyBridge \
    --version "$VERSION" \
    --install-location /Applications \
    build/temp.pkg

cat > build/distribution.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>ProxyBridge</title>
    <pkg-ref id="com.interceptsuite.ProxyBridge"/>
    <!-- without hostArchitectures the Installer on Apple silicon assumes an Intel-only package and offers to
         install Rosetta. the app and the extension are universal (verified above), so say so -->
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.interceptsuite.ProxyBridge"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.interceptsuite.ProxyBridge" visible="false">
        <pkg-ref id="com.interceptsuite.ProxyBridge"/>
    </choice>
    <pkg-ref id="com.interceptsuite.ProxyBridge" version="4.1.0" onConclusion="none">temp.pkg</pkg-ref>
</installer-gui-script>
EOF

productbuild \
    --distribution build/distribution.xml \
    --package-path build \
    output/ProxyBridge-v$VERSION-Universal-Installer.pkg

echo "Package created: output/ProxyBridge-v$VERSION-Universal-Installer.pkg"

if [ -n "$APPLE_ID" ] && [ -n "$APPLE_APP_PASSWORD" ] && [ -n "$SIGNING_IDENTITY" ]; then
    echo "Signing installer..."
    productsign --sign "$SIGNING_IDENTITY" \
        output/ProxyBridge-v$VERSION-Universal-Installer.pkg \
        output/ProxyBridge-v$VERSION-Universal-Installer-signed.pkg

    mv output/ProxyBridge-v$VERSION-Universal-Installer-signed.pkg output/ProxyBridge-v$VERSION-Universal-Installer.pkg

    echo "Notarizing installer..."
    xcrun notarytool submit output/ProxyBridge-v$VERSION-Universal-Installer.pkg \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait

    echo "Stapling notarization ticket..."
    xcrun stapler staple output/ProxyBridge-v$VERSION-Universal-Installer.pkg
    echo "Installer signed and notarized"
else
    echo "Skipping signing/notarization - set APPLE_ID, APPLE_APP_PASSWORD, SIGNING_IDENTITY, and TEAM_ID in .env"
fi

rm -rf build

echo "✓ Build complete"
echo "  App: output/ProxyBridge.app"
echo "  PKG: output/ProxyBridge-v$VERSION-Universal-Installer.pkg"

#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="$SCRIPT_DIR/output/ProxyBridge.app"

if [ ! -d "$APP_PATH" ]; then
    echo "Error: ProxyBridge.app not found in output directory"
    echo "Export the app from Xcode to output/ first"
    exit 1
fi

mkdir -p "$SCRIPT_DIR/build/component"

cp -R "$APP_PATH" "$SCRIPT_DIR/build/component/"

echo "Creating installer package..."

pkgbuild \
    --root build/component \
    --identifier com.interceptsuite.ProxyBridge \
    --version 3.0.0 \
    --install-location /Applications \
    build/temp.pkg

cat > build/distribution.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>ProxyBridge</title>
    <pkg-ref id="com.interceptsuite.ProxyBridge"/>
    <options customize="never" require-scripts="false"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.interceptsuite.ProxyBridge"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.interceptsuite.ProxyBridge" visible="false">
        <pkg-ref id="com.interceptsuite.ProxyBridge"/>
    </choice>
    <pkg-ref id="com.interceptsuite.ProxyBridge" version="3.0.0" onConclusion="none">temp.pkg</pkg-ref>
</installer-gui-script>
EOF

productbuild \
    --distribution build/distribution.xml \
    --package-path build \
    output/ProxyBridge-Installer.pkg

echo "Package created: output/ProxyBridge-Installer.pkg"

if [ -n "$APPLE_ID" ] && [ -n "$APPLE_APP_PASSWORD" ]; then
    echo "Notarizing installer..."
    xcrun notarytool submit output/ProxyBridge-Installer.pkg \
        --apple-id "$APPLE_ID" \
        --team-id "" \
        --password "$APPLE_APP_PASSWORD" \
        --wait
    
    echo "Stapling notarization ticket..."
    xcrun stapler staple output/ProxyBridge-Installer.pkg
    echo "Installer notarized"
else
    echo "Skipping notarization - set APPLE_ID and APPLE_APP_PASSWORD to notarize"
fi

rm -rf build

echo "✓ Build complete"
echo "  App: output/ProxyBridge.app"
echo "  PKG: output/ProxyBridge-Installer.pkg"

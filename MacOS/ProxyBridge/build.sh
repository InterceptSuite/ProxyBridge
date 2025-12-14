#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -rf "$SCRIPT_DIR/output"
mkdir -p "$SCRIPT_DIR/output"

xcodebuild \
    -project ProxyBridge.xcodeproj \
    -scheme ProxyBridge \
    -configuration Release \
    -derivedDataPath build/DerivedData \
    ARCHS="arm64 x86_64" \
    ONLY_ACTIVE_ARCH=NO \
    CODE_SIGN_IDENTITY="-" \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGNING_ALLOWED=NO \
    clean build

cp -R build/DerivedData/Build/Products/Release/ProxyBridge.app output/

mkdir -p build/component
cp -R output/ProxyBridge.app build/component/

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

rm -rf build

echo "✓ Build complete"
echo "  App: output/ProxyBridge.app"
echo "  PKG: output/ProxyBridge-Installer.pkg"

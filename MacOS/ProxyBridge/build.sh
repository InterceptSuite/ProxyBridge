#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

PROJECT_NAME="ProxyBridge"
SCHEME_NAME="ProxyBridge"
OUTPUT_DIR="$SCRIPT_DIR/output"
PKG_NAME="ProxyBridge-v3.0-Universal-Installer.pkg"
PKG_PATH="$OUTPUT_DIR/$PKG_NAME"
APP_NAME="${PROJECT_NAME}.app"
APP_PATH="$OUTPUT_DIR/$APP_NAME"
LICENSE_FILE="$SCRIPT_DIR/../../LICENSE"

SIGN_PKG=${SIGN_PKG:-""}
NOTARIZE=${NOTARIZE:-""}
APPLE_ID=${APPLE_ID:-""}
TEAM_ID=${TEAM_ID:-""}
APP_PASSWORD=${APP_PASSWORD:-""}

echo "Creating PKG installer from notarized app..."

# Check if app exists
if [ ! -d "$APP_PATH" ]; then
    echo "Error: $APP_NAME not found in $OUTPUT_DIR"
    echo "Please export the notarized app from Xcode to the output folder first."
    exit 1
fi

# Remove old PKG if exists
if [ -f "$PKG_PATH" ]; then
    echo "Removing old PKG..."
    rm -f "$PKG_PATH"
fi

echo "Verifying app signature..."
codesign --verify --verbose=2 --deep --strict "$APP_PATH"

echo "Verifying universal binary..."
lipo -info "$APP_PATH/Contents/MacOS/$PROJECT_NAME"

echo "Verifying universal binary..."
lipo -info "$APP_PATH/Contents/MacOS/$PROJECT_NAME"

echo "Creating PKG installer..."

COMPONENT_DIR="$SCRIPT_DIR/build/component"
TEMP_PKG="$SCRIPT_DIR/build/temp.pkg"
DISTRIBUTION_FILE="$SCRIPT_DIR/build/distribution.xml"

mkdir -p "$SCRIPT_DIR/build"
mkdir -p "$COMPONENT_DIR"
cp -R "$APP_PATH" "$COMPONENT_DIR/"

pkgbuild \
    --root "$COMPONENT_DIR" \
    --identifier "com.interceptsuite.${PROJECT_NAME}" \
    --version "3.0.0" \
    --install-location "/Applications" \
    "$TEMP_PKG"

if [ $? -ne 0 ]; then
    echo "PKG creation failed!"
    exit 1
fi

cat > "$DISTRIBUTION_FILE" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>ProxyBridge</title>
    <license file="LICENSE"/>
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

if [ -n "$SIGN_PKG" ]; then
    echo "Signing PKG installer..."
    productbuild \
        --distribution "$DISTRIBUTION_FILE" \
        --resources "$SCRIPT_DIR/../../" \
        --package-path "$SCRIPT_DIR/build" \
        --sign "$SIGN_PKG" \
        "$PKG_PATH"
else
    echo "Creating unsigned PKG..."
    productbuild \
        --distribution "$DISTRIBUTION_FILE" \
        --resources "$SCRIPT_DIR/../../" \
        --package-path "$SCRIPT_DIR/build" \
        "$PKG_PATH"
fi

if [ $? -ne 0 ]; then
    echo "Product PKG creation failed!"
    exit 1
fi

echo "PKG installer created successfully!"
echo "PKG Location: $PKG_PATH"
echo "PKG Size: $(du -h "$PKG_PATH" | cut -f1)"

if [ -n "$NOTARIZE" ] && [ -n "$APPLE_ID" ] && [ -n "$APP_PASSWORD" ] && [ -n "$TEAM_ID" ]; then
    echo "Notarizing PKG..."
    
    xcrun notarytool submit "$PKG_PATH" \
        --apple-id "$APPLE_ID" \
        --password "$APP_PASSWORD" \
        --team-id "$TEAM_ID" \
        --wait
    
    if [ $? -eq 0 ]; then
        echo "Stapling notarization ticket to PKG..."
        xcrun stapler staple "$PKG_PATH"
        
        if [ $? -eq 0 ]; then
            echo "PKG notarized and stapled successfully!"
        else
            echo "Warning: Stapling failed but notarization succeeded"
        fi
    else
        echo "Warning: Notarization failed"
    fi
fi

echo "Cleaning up build artifacts..."
rm -rf "$SCRIPT_DIR/build"

echo "Build complete!"

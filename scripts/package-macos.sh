#!/bin/sh
# Package a built httpsdiag binary into a macOS .app bundle so Finder shows it
# as a double-clickable application. The bundle is NOT code-signed; macOS
# Gatekeeper will warn on first open (right-click -> Open, or clear the
# quarantine attribute).
#
# Usage: scripts/package-macos.sh <binary> <version> <outdir>
set -eu

BIN="${1:?usage: package-macos.sh <binary> <version> <outdir>}"
VERSION="${2:-0.0.0-dev}"
OUT="${3:-dist}"

APP_NAME="HTTPS Diagnostic Workbench"
APP="$OUT/$APP_NAME.app"
SHORT=$(printf '%s' "$VERSION" | sed 's/^v//')

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/httpsdiag"
chmod +x "$APP/Contents/MacOS/httpsdiag"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>com.dimarcotech.httpsdiag</string>
  <key>CFBundleExecutable</key>
  <string>httpsdiag</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$SHORT</string>
  <key>CFBundleVersion</key>
  <string>$SHORT</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "built $APP"

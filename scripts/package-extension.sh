#!/usr/bin/env bash
# Package the Aegis Browser Extension for distribution.
# Produces .zip files AND unpacked directories for Chrome/Brave and Firefox.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXT_DIR="${SCRIPT_DIR}/../extension"
DIST_DIR="${SCRIPT_DIR}/../dist/extension"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "=== Packaging Aegis Browser Extension ==="

# ─── Chrome / Brave / Chromium (Manifest V3) ────────────────────────────────
echo ""
echo "[1/2] Chrome / Brave / Chromium (MV3)..."

CHROME_DIR="$DIST_DIR/chrome"
mkdir -p "$CHROME_DIR"
cp "$EXT_DIR"/manifest.chrome.json "$CHROME_DIR/manifest.json"
cp "$EXT_DIR"/background.js      "$CHROME_DIR/"
cp "$EXT_DIR"/browser-control.js "$CHROME_DIR/"
cp "$EXT_DIR"/content.js         "$CHROME_DIR/"
cp "$EXT_DIR"/popup.html         "$CHROME_DIR/"
cp "$EXT_DIR"/popup.js           "$CHROME_DIR/"
cp -r "$EXT_DIR"/icons           "$CHROME_DIR/"
cp "$EXT_DIR"/README.md          "$CHROME_DIR/"

CHROME_ZIP="$DIST_DIR/aegis-connector-chrome.zip"
(cd "$CHROME_DIR" && zip -r "$CHROME_ZIP" .)
echo "  -> $CHROME_DIR"
echo "  -> $CHROME_ZIP"

# ─── Firefox (Manifest V2) ─────────────────────────────────────────────────
echo "[2/2] Firefox (MV2)..."

FIREFOX_DIR="$DIST_DIR/firefox"
mkdir -p "$FIREFOX_DIR"
cp "$EXT_DIR"/manifest.firefox.json "$FIREFOX_DIR/manifest.json"
cp "$EXT_DIR"/background.js         "$FIREFOX_DIR/"
cp "$EXT_DIR"/browser-control.js    "$FIREFOX_DIR/"
cp "$EXT_DIR"/content.js            "$FIREFOX_DIR/"
cp "$EXT_DIR"/popup.html            "$FIREFOX_DIR/"
cp "$EXT_DIR"/popup.js              "$FIREFOX_DIR/"
cp -r "$EXT_DIR"/icons              "$FIREFOX_DIR/"
cp "$EXT_DIR"/README.md             "$FIREFOX_DIR/"

FIREFOX_ZIP="$DIST_DIR/aegis-connector-firefox.zip"
(cd "$FIREFOX_DIR" && zip -r "$FIREFOX_ZIP" .)
echo "  -> $FIREFOX_DIR"
echo "  -> $FIREFOX_ZIP"

echo ""
echo "=== Done ==="
echo ""
echo "Load unpacked (developer mode):"
echo "  Chrome:  chrome://extensions -> Load unpacked -> select $CHROME_DIR"
echo "  Brave:   brave://extensions  -> Load unpacked -> select $CHROME_DIR"
echo "  Firefox: about:debugging#/runtime/this-firefox -> Load Temporary Add-on -> select $FIREFOX_DIR/manifest.json"
echo ""
echo "Chrome Web Store upload: $CHROME_ZIP (manifest.json is at ZIP root)."
echo "Firefox permanent distribution requires Mozilla signing; this ZIP is unsigned."

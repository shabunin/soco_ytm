#!/usr/bin/env bash
#
# patch_sonos.sh — make a debuggable, Frida-attachable copy of Sonos.app.
#
# Apple's /Applications/Sonos.app is signed with "hardened runtime", which forbids
# task_for_pid() and therefore blocks Frida/lldb. This script copies the app and
# re-signs the COPY with an adhoc signature + the `get-task-allow` entitlement (and
# disables library validation). The ORIGINAL is never modified.
#
# Usage:
#   ./patch_sonos.sh [/path/to/Sonos.app] [/path/to/output/SonosPatched.app]
# Defaults:
#   src = /Applications/Sonos.app
#   dst = ./SonosPatched.app   (next to this script)
#
set -euo pipefail

SRC="${1:-/Applications/Sonos.app}"
DST="${2:-$(cd "$(dirname "$0")" && pwd)/SonosPatched.app}"
ENT="$(mktemp -t sonos-ent).plist"

cleanup() { rm -f "$ENT"; }
trap cleanup EXIT

[ -d "$SRC" ] || { echo "[!] source app not found: $SRC" >&2; exit 1; }
command -v codesign >/dev/null || { echo "[!] codesign not found (install Xcode CLT: xcode-select --install)" >&2; exit 1; }

echo "[*] source : $SRC"
echo "[*] output : $DST"

# 1) fresh copy (preserve symlinks/attrs inside the bundle)
rm -rf "$DST"
echo "[*] copying bundle…"
cp -a "$SRC" "$DST"

# 2) entitlements that make the copy debuggable
cat > "$ENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
</dict>
</plist>
PLIST

# 3) deep adhoc re-sign (nested frameworks/helpers first, then the app).
#    --force replaces the hardened-runtime signature; "-" = adhoc (no Team/identity).
echo "[*] re-signing (adhoc, deep) with get-task-allow…"
codesign --remove-signature "$DST" 2>/dev/null || true
codesign --force --deep --sign - \
         --entitlements "$ENT" \
         --options "" \
         "$DST"

# Remove quarantine attribute so LaunchServices can execute the adhoc build
xattr -cr "$DST" 2>/dev/null || true

# 4) verify
echo "[*] verifying signature…"
if codesign -dv --entitlements - "$DST" 2>&1 | grep -q "get-task-allow"; then
    FLAGS=$(codesign -dv "$DST" 2>&1 | grep -oE 'flags=0x[0-9a-f]+\([^)]*\)' || true)
    echo "[✓] patched OK — $FLAGS, entitlement get-task-allow present"
else
    echo "[!] signing finished but get-task-allow not found — check codesign output above" >&2
    exit 1
fi

echo
echo "Done. Launch the patched copy, e.g.:"
echo "    open \"$DST\""
echo "then open YouTube Music in it once, and run:"
echo "    python3 extract_apikey.py"

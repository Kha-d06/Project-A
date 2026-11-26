#!/usr/bin/env bash
# Checks the macOS build's code signature and notarisation (docs/code-signing.md).
#   SIGNED=true    a Developer ID certificate was configured: the checks must pass.
#   REQUIRED=true  an unsigned build is an error (tagged releases with REQUIRE_SIGNED_RELEASES).
# Usage: verify-signatures.sh macos <release-dir>
set -euo pipefail
platform="${1:?macos}"
dir="${2:?release dir}"
[ "$platform" = macos ] || { echo "Only macos is checked here; Windows uses verify-signatures.ps1." >&2; exit 2; }

app="$(find "$dir" -maxdepth 3 -name '*.app' -type d | head -n 1)"
[ -n "$app" ] || { echo "::error::No .app bundle in $dir"; exit 1; }

if [ "${SIGNED:-false}" != "true" ]; then
  if [ "${REQUIRED:-false}" = "true" ]; then
    echo "::error::REQUIRE_SIGNED_RELEASES is on, but no Developer ID certificate is configured."
    exit 1
  fi
  echo "::warning::macOS build is unsigned: Gatekeeper will warn, and the app can't update itself."
  exit 0
fi

# Signature valid and complete, hardened runtime on, and Gatekeeper accepts it as notarised.
codesign --verify --deep --strict --verbose=2 "$app"
codesign --display --verbose=4 "$app" 2>&1 | grep -E "^(Authority|TeamIdentifier|Runtime)" || true
codesign --display --verbose=4 "$app" 2>&1 | grep -q "flags=0x10000(runtime)" || { echo "::error::Hardened runtime is off."; exit 1; }
spctl --assess --type execute --verbose=4 "$app"
xcrun stapler validate "$app"
for dmg in "$dir"/*.dmg; do
  [ -e "$dmg" ] || continue
  codesign --verify --verbose=2 "$dmg" || echo "::warning::$dmg itself isn't signed (the app inside is)."
done
echo "macOS signature and notarisation verified for $app"

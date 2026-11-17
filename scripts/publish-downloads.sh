#!/usr/bin/env bash
# Copy release files (from a GitHub release or local builds) into ./downloads,
# which Caddy serves at <site>/downloads/. The desktop app updates itself from
# downloads/desktop/latest*.yml; the website's Download page lists what is here.
#
#   ./scripts/publish-downloads.sh ~/Downloads/sentinel-release
set -euo pipefail
cd "$(dirname "$0")/.."
src="${1:?Usage: $0 <folder with release files>}"
mkdir -p downloads/desktop downloads/android

shopt -s nullglob
copied=0
for file in "$src"/*.{AppImage,deb,rpm,exe,dmg,zip,blockmap} "$src"/latest*.yml; do
  cp -f "$file" downloads/desktop/ && copied=$((copied + 1))
done

apk=""
for file in "$src"/*.apk; do apk="$file"; done
if [ -n "$apk" ]; then
  name="$(basename "$apk")"
  cp -f "$apk" "downloads/android/$name"
  sha="$(sha256sum "$apk" | cut -d' ' -f1)"
  version="$(echo "$name" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  printf '{"version": "%s", "file": "%s", "sha256": "%s"}\n' "${version:-unknown}" "$name" "$sha" > downloads/android/latest.json
  copied=$((copied + 1))
fi

echo "Published $copied file(s) to downloads/. They are live at <your site>/downloads/ (no restart needed)."

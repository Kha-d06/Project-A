#!/usr/bin/env bash
# Builds every part whose output should be byte-for-byte reproducible, from one
# checkout, into <out>. Run it twice from two separate checkouts of the same
# commit and compare the results with compare.py (docs/reproducible-builds.md).
#
#   build-all.sh <checkout> <out> [js|rust|all]
#
# Inputs that would otherwise vary are fixed:
#   SOURCE_DATE_EPOCH  the commit time, for archive timestamps
#   FILTER_LIST_DIR    the extension's EasyList/EasyPrivacy files (downloaded once, outside)
#   RUSTFLAGS          the checkout path and home folder remapped out of the binaries
# No signing key is used or needed: signatures are added after this, offline.
set -euo pipefail
src="$(cd "${1:?checkout}" && pwd)"
out="$(mkdir -p "${2:?out}" && cd "$2" && pwd)"
what="${3:-all}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$src" log -1 --format=%ct)}"
export TZ=UTC LC_ALL=C
# The bundles don't need the Electron runtime itself.
export ELECTRON_SKIP_BINARY_DOWNLOAD=1

if [ "$what" = js ] || [ "$what" = all ]; then
  : "${FILTER_LIST_DIR:?set FILTER_LIST_DIR to the downloaded filter lists}"
  (cd "$src/apps/extension" && npm ci --no-audit --no-fund >/dev/null && NODE_ENV=production npm run build >/dev/null && NODE_ENV=production npm run build:firefox >/dev/null)
  mkdir -p "$out/extension" && cp -r "$src/apps/extension/dist/." "$out/extension/"
  (cd "$src/apps/desktop" && npm ci --no-audit --no-fund >/dev/null && NODE_ENV=production npm run build >/dev/null)
  mkdir -p "$out/desktop-dist" && cp -r "$src/apps/desktop/dist/." "$out/desktop-dist/"
  (cd "$src/apps/thunderbird" && npm run pack >/dev/null)
  mkdir -p "$out/thunderbird" && cp "$src"/apps/thunderbird/dist/*.xpi "$out/thunderbird/"
fi

if [ "$what" = rust ] || [ "$what" = all ]; then
  export CARGO_INCREMENTAL=0
  export RUSTFLAGS="--remap-path-prefix=$src=/qalaa --remap-path-prefix=$out=/out --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo -C link-arg=-Wl,--build-id=none"
  (cd "$src/apps/desktop-native" && cargo build --release --locked -p qalaa-scan -p qalaa-dns --target-dir "$out/.target" >/dev/null 2>&1)
  mkdir -p "$out/native"
  cp "$out/.target/release/qalaa-scan" "$out/.target/release/qalaa-dns" "$out/native/"
  rm -rf "$out/.target"
fi
echo "Built $what from $src into $out (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"

# Reproducible builds

Anyone with the source of a commit should be able to rebuild Qalaa's artifacts
and get the same bytes. Then a release can be checked against its source, and a
build machine that was tampered with produces a visible difference. The check
lives in `.github/workflows/reproducible.yml`.
- **When it runs:** every push and pull request, weekly, and on demand.
- **What it does:** builds the commit twice, from two separate checkouts with separate caches, and fails on any difference.
- **Report:** the per-file SHA-256 report is uploaded as an artifact.

Run it yourself:

```sh
git clone https://github.com/Kha-d06/Project-A a && git clone https://github.com/Kha-d06/Project-A b   # same commit in both
mkdir lists && curl -fsSL https://easylist.to/easylist/easylist.txt -o lists/easylist.txt \
            && curl -fsSL https://easylist.to/easylist/easyprivacy.txt -o lists/easyprivacy.txt
FILTER_LIST_DIR=$PWD/lists a/scripts/reproducibility/build-all.sh a out-a all
FILTER_LIST_DIR=$PWD/lists b/scripts/reproducibility/build-all.sh b out-b all
python3 a/scripts/reproducibility/compare.py out-a out-b
```

## What is reproducible

| Artifact | Status | Verified |
|---|---|---|
| Browser extension, Chrome and Firefox builds (`apps/extension/dist`) | Byte-for-byte | Locally: two separate copies, all files identical; CI job `javascript` |
| Desktop service and Electron bundles (`apps/desktop/dist`) | Byte-for-byte | Same |
| Thunderbird add-on `.xpi` | Byte-for-byte: sorted entries, fixed timestamps from `SOURCE_DATE_EPOCH`, no extra attributes | Same |
| `qalaa-dns` (Linux x86-64 release) | Byte-for-byte when built from different paths | Locally: identical SHA-256 |
| `qalaa-scan` (Linux x86-64 release) | Byte-for-byte when built from different paths | Locally, with `build-all.sh`: identical SHA-256; CI job `native` |
| Desktop installers (AppImage, .deb, .rpm, NSIS .exe, .dmg) | **Not reproducible yet** | — |
| `qalaa-command`, `qalaa-guardian-pet` | Not in the check yet: they need the Slint system libraries on the runner | — |
| Android APK | Not checked | — |
| Server container images | Not checked: base images are tags, not digests | — |

## How the variation is removed

- **Same source:** both checkouts are verified to be `$GITHUB_SHA`.
- **Same dependencies:**
  - npm installs only from `package-lock.json` (`npm ci`, integrity-checked), each side with its own empty cache;
  - Cargo builds with `--locked` from `Cargo.lock`.
- **Same tools:**
  - Node is an exact version in the workflow (22.23.5);
  - Rust is pinned in `apps/desktop-native/rust-toolchain.toml` (1.97.0), which CI and local builds both obey;
  - esbuild, TypeScript and electron-builder are exact versions in the lockfiles.
- **Same external input:** the extension's EasyList and EasyPrivacy files are downloaded once and given to both builds (`FILTER_LIST_DIR`), with their SHA-256 printed in the log. A release build records which lists it used the same way.
- **No time or place in the output:**
  - `SOURCE_DATE_EPOCH` is the commit time;
  - archive timestamps come from it;
  - Rust paths are remapped (`--remap-path-prefix`) for the checkout, the target folder and Cargo's home;
  - the linker's random build ID is turned off;
  - `CARGO_INCREMENTAL=0`.
- **No secrets:** signing happens after this, offline, and isn't compared. The check needs no key, certificate or token.

## Why the installers aren't reproducible yet

- **electron-builder:** it writes timestamps and file order into the AppImage squashfs, the .deb and .rpm archives and the NSIS installer, and doesn't honour `SOURCE_DATE_EPOCH` everywhere.
- **Code signing:** Authenticode and Developer ID signatures embed a timestamp, so signed installers differ by design.

The plan:
1. compare the **unpacked** application (`app.asar` contents and the bundled binaries) before packaging, which are the bundles above;
2. then make the Linux packages reproducible (fixed mtimes, sorted squashfs, `SOURCE_DATE_EPOCH` for dpkg/rpm);
3. for signed installers, publish the unsigned build's hash next to the signed one, so the signature can be stripped and compared.

## What a passing check does and doesn't prove

- **Proves:** two independent builds of the commit, on two runners' worth of clean state, gave the same artifacts. So the artifacts are a function of the source and the pinned inputs.
- **Doesn't prove:** that the pinned inputs themselves are trustworthy (a compromised npm package in the lockfile is reproduced faithfully). That is what the SBOMs, `npm audit` and the lockfile reviews are for.
- **Same build system:** both builds run on GitHub's runners. An independent rebuild on your own machine, with the commands above, is the stronger check.

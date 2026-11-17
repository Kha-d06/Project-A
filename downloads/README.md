# Downloads

Installers and update feeds served by Caddy at `<your site>/downloads/`.

```
downloads/
  desktop/   SENTINEL-Desktop-<version>-*.{AppImage,deb,rpm,exe,dmg,zip}
             latest.yml, latest-linux.yml, latest-mac.yml   (auto-update feeds)
  android/   SENTINEL-<version>.apk, latest.json
```

Fill it with `./scripts/publish-downloads.sh <folder-with-release-files>`, for example
the files from a GitHub release or the `release/` folder of a local desktop build.
Nothing in here is committed to git.

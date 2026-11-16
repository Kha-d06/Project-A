// @ts-expect-error: plain ES module without type declarations
import { createManifest } from "../scripts/manifest.mjs";

describe("manifest", () => {
  const base = { version: "1.2.3", serverOrigin: "https://sentinel.example" };

  it("keeps permissions minimal and scoped to the configured server", () => {
    const manifest = createManifest(base);
    expect(manifest.permissions).toEqual(["storage", "webNavigation", "downloads", "notifications", "contextMenus", "activeTab"]);
    expect(manifest.host_permissions).toEqual(["https://sentinel.example/*"]);
    // Access to web pages is only ever requested at runtime, for hover checks.
    expect(manifest.optional_host_permissions).toEqual(["http://*/*", "https://*/*"]);
    expect(manifest).not.toHaveProperty("externally_connectable");
    expect(manifest).not.toHaveProperty("content_scripts");
  });

  it("uses a service worker for Chromium browsers", () => {
    const manifest = createManifest(base);
    expect(manifest.background).toEqual({ service_worker: "background.js", type: "module" });
    expect(manifest.minimum_chrome_version).toBe("116");
  });

  it("uses an event page and a gecko id for Firefox", () => {
    const manifest = createManifest({ ...base, browser: "firefox" });
    expect(manifest.background).toEqual({ scripts: ["background.js"], type: "module" });
    expect(manifest.browser_specific_settings.gecko.strict_min_version).toBe("128.0");
    expect(manifest).not.toHaveProperty("minimum_chrome_version");
  });
});

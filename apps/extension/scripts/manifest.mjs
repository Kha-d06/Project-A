/**
 * Builds manifest.json. Permissions are kept to what the features need; each one
 * is explained to the user on the welcome page (static/welcome.html).
 *
 * browser: "chrome" (also Microsoft Edge and other Chromium browsers) or
 * "firefox" (experimental: built but not yet tested in Firefox).
 */
export function createManifest({ version, serverOrigin, browser = "chrome" }) {
  const manifest = {
    manifest_version: 3,
    name: "SENTINEL Protect",
    short_name: "SENTINEL",
    version,
    description: "Warns you before known dangerous sites load and checks links and downloads. Free.",
    icons: { 16: "icons/icon-16.png", 32: "icons/icon-32.png", 48: "icons/icon-48.png", 128: "icons/icon-128.png" },
    action: {
      default_title: "SENTINEL Protect",
      default_popup: "popup.html",
      default_icon: { 16: "icons/icon-16.png", 32: "icons/icon-32.png" },
    },
    options_ui: { page: "options.html", open_in_tab: true },
    permissions: ["storage", "webNavigation", "downloads", "notifications", "contextMenus", "activeTab"],
    // Requested only when the user turns on hover checks or picks another server.
    optional_permissions: ["scripting"],
    host_permissions: [`${serverOrigin}/*`],
    optional_host_permissions: ["http://*/*", "https://*/*"],
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    },
  };

  if (browser === "firefox") {
    return {
      ...manifest,
      // Firefox runs Manifest V3 background code as an event page, not a service worker.
      background: { scripts: ["background.js"], type: "module" },
      browser_specific_settings: {
        gecko: { id: "protect@sentinel-security.invalid", strict_min_version: "128.0" },
      },
    };
  }
  return {
    ...manifest,
    minimum_chrome_version: "116",
    background: { service_worker: "background.js", type: "module" },
  };
}

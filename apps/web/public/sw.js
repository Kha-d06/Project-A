/*
 * Qalaa service worker.
 *
 * Deliberately minimal: it caches only the offline notice, so pages, scan
 * results and API responses are never stored on the device and never shown
 * stale. When a navigation fails because there is no network, the offline
 * notice explains that nothing could be checked.
 */
const CACHE = "sentinel-offline-v1";
const OFFLINE_URL = "/offline";

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.add(new Request(OFFLINE_URL, { cache: "reload" }))));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))),
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.mode !== "navigate") return;
  event.respondWith(fetch(event.request).catch(() => caches.match(OFFLINE_URL)));
});

// Web Push: notifications carry only a title, a sentence and a link back to
// Qalaa, never anything that was scanned.
self.addEventListener("push", (event) => {
  let data = { title: "Qalaa", body: "", url: "/dashboard" };
  try {
    data = { ...data, ...event.data.json() };
  } catch {
    // keep the defaults
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      data: { url: data.url },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const path = event.notification.data?.url ?? "/dashboard";
  // Only ever open pages on this site.
  const target = new URL(path, self.location.origin);
  if (target.origin !== self.location.origin) return;
  event.waitUntil(self.clients.openWindow(target.href));
});

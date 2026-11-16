"use client";

import { useEffect } from "react";

/** Registers the offline-notice service worker in production builds only. */
export function ServiceWorker() {
  useEffect(() => {
    if (process.env.NODE_ENV !== "production" || !("serviceWorker" in navigator)) return;
    navigator.serviceWorker.register("/sw.js").catch(() => {
      // Without it the site still works; only the offline notice is missing.
    });
  }, []);
  return null;
}

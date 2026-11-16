import type { MetadataRoute } from "next";

/**
 * Installable web app. On Android, the share target puts SENTINEL in the system
 * share sheet, so a suspicious link or message can be sent to it from any app.
 */
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "SENTINEL: check links, messages and files",
    short_name: "SENTINEL",
    description: "Check suspicious links, messages, files, QR codes and apps. Free.",
    id: "/",
    start_url: "/scan",
    scope: "/",
    display: "standalone",
    background_color: "#080d17",
    theme_color: "#080d17",
    categories: ["security", "utilities"],
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
      { src: "/icons/maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
    share_target: {
      action: "/share",
      method: "GET",
      params: { title: "title", text: "text", url: "url" },
    },
    shortcuts: [
      { name: "Check a link", url: "/scan?type=url" },
      { name: "Analyse a message", url: "/scan?type=message" },
      { name: "Scan a QR code", url: "/scan?type=qr" },
    ],
  };
}

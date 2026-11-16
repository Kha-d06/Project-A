import "@fontsource-variable/inter";
import "@fontsource-variable/manrope";
import "@fontsource-variable/jetbrains-mono";
import "./globals.css";

import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";

import { ToastProvider } from "@/components/ui/toast";
import { SessionProvider } from "@/lib/session";
import { themeBootScript } from "@/lib/theme";

export const metadata: Metadata = {
  title: { default: "SENTINEL: check links, messages and files", template: "%s · SENTINEL" },
  description:
    "SENTINEL helps you spot phishing links, scam messages and malicious files, and explains what it found in plain language. Free for everyone.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f5f6f8" },
    { media: "(prefers-color-scheme: dark)", color: "#080d17" },
  ],
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: themeBootScript }} />
      </head>
      <body className="min-h-dvh">
        <a
          href="#main"
          className="sr-only z-50 rounded-control bg-accent px-4 py-2 text-accent-ink focus:not-sr-only focus:fixed focus:start-4 focus:top-4"
        >
          Skip to content
        </a>
        <SessionProvider>
          <ToastProvider>{children}</ToastProvider>
        </SessionProvider>
      </body>
    </html>
  );
}

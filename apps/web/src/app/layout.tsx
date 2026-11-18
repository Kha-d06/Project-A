import "@fontsource-variable/instrument-sans";
import "@fontsource-variable/bricolage-grotesque";
import "@fontsource-variable/noto-kufi-arabic";
import "@fontsource-variable/jetbrains-mono";
import "@fontsource-variable/noto-sans-arabic";
import "./globals.css";

import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";

import { ServiceWorker } from "@/components/site/service-worker";
import { ToastProvider } from "@/components/ui/toast";
import { I18nProvider } from "@/lib/i18n/client";
import { directionOf } from "@/lib/i18n/locales";
import { getDictionary, getLocale } from "@/lib/i18n/server";
import { SessionProvider } from "@/lib/session";
import { themeBootScript } from "@/lib/theme";

export const metadata: Metadata = {
  appleWebApp: { capable: true, title: "Qalaa", statusBarStyle: "black-translucent" },
  icons: { apple: "/icons/apple-touch-icon.png" },
  title: { default: "Qalaa: check links, messages and files", template: "%s · Qalaa" },
  description:
    "Qalaa helps you spot phishing links, scam messages and malicious files, and explains what it found in plain language. Free for everyone.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f7f4ee" },
    { media: "(prefers-color-scheme: dark)", color: "#070b16" },
  ],
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  const locale = await getLocale();
  const t = getDictionary(locale);
  return (
    <html lang={locale} dir={directionOf(locale)} suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: themeBootScript }} />
      </head>
      <body className="min-h-dvh">
        <a
          href="#main"
          className="sr-only z-50 rounded-control bg-accent px-4 py-2 text-accent-ink focus:not-sr-only focus:fixed focus:start-4 focus:top-4"
        >
          {t.nav.skip}
        </a>
        <ServiceWorker />
        <I18nProvider locale={locale}>
          <SessionProvider>
            <ToastProvider>{children}</ToastProvider>
          </SessionProvider>
        </I18nProvider>
      </body>
    </html>
  );
}

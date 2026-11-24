// One bilingual family (Latin and Arabic drawn together), plus mono for real data only.
import "@fontsource-variable/ibm-plex-sans";
import "@fontsource/ibm-plex-sans-arabic/400.css";
import "@fontsource/ibm-plex-sans-arabic/500.css";
import "@fontsource/ibm-plex-sans-arabic/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./globals.css";

import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";

import { ServiceWorker } from "@/components/site/service-worker";
import { ToastProvider } from "@/components/ui/toast";
import { I18nProvider } from "@/lib/i18n/client";
import { directionOf } from "@/lib/i18n/locales";
import { getDictionary, getLocale } from "@/lib/i18n/server";
import { siteUrl } from "@/lib/seo";
import { SessionProvider } from "@/lib/session";
import { themeBootScript } from "@/lib/theme";

export const generateMetadata = async (): Promise<Metadata> => ({
  metadataBase: new URL(siteUrl()),
  applicationName: "Qalaa",
  openGraph: { type: "website", siteName: "Qalaa", images: [{ url: "/icons/icon-512.png", width: 512, height: 512, alt: "Qalaa" }] },
  twitter: { card: "summary" },
  appleWebApp: { capable: true, title: "Qalaa", statusBarStyle: "black-translucent" },
  icons: { apple: "/icons/apple-touch-icon.png" },
  title: { default: "Qalaa: check links, messages and files", template: "%s · Qalaa" },
  description:
    "Qalaa helps you spot phishing links, scam messages and malicious files, and explains what it found in plain language. Free for everyone.",
});

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f4f5f7" },
    { media: "(prefers-color-scheme: dark)", color: "#0b0e15" },
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

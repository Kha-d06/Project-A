import type { Metadata } from "next";
import { headers } from "next/headers";

import { JsonLd } from "@/components/seo/json-ld";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { getLocale } from "@/lib/i18n/server";
import { alternates, breadcrumbLd, breadcrumbs, isPrivatePath, organizationLd, websiteLd } from "@/lib/seo";

async function currentPath(): Promise<string> {
  return (await headers()).get("x-pathname") ?? "/";
}

/** Canonical and hreflang for every public page; private pages are never indexed. */
export async function generateMetadata(): Promise<Metadata> {
  const [path, locale] = await Promise.all([currentPath(), getLocale()]);
  if (isPrivatePath(path)) return { robots: { index: false, follow: false } };
  return {
    alternates: alternates(path, locale),
    openGraph: { locale: locale === "ar" ? "ar_AE" : "en_US", alternateLocale: locale === "ar" ? ["en_US"] : ["ar_AE"], url: alternates(path, locale).canonical },
  };
}

export default async function SiteLayout({ children }: { children: React.ReactNode }) {
  const [path, locale] = await Promise.all([currentPath(), getLocale()]);
  // Articles add their own breadcrumb, with the article's title.
  const crumbs = path.startsWith("/learn/") || isPrivatePath(path) ? null : breadcrumbs(path, locale);
  return (
    <div className="flex min-h-dvh flex-col">
      <JsonLd data={[organizationLd(), websiteLd(), ...(crumbs && crumbs.length > 1 ? [breadcrumbLd(crumbs)] : [])]} />
      <SiteHeader />
      <main id="main" className="flex-1">
        {children}
      </main>
      <SiteFooter />
    </div>
  );
}

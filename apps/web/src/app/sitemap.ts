import type { MetadataRoute } from "next";
import { connection } from "next/server";

import { ARTICLES } from "@/content/awareness";
import { sitemapEntries } from "@/lib/seo";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  // The site address is a deployment setting, read per request.
  await connection();
  return sitemapEntries(
    ARTICLES.map((a) => a.slug),
    new Date(),
  );
}

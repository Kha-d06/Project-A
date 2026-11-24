import type { MetadataRoute } from "next";
import { connection } from "next/server";

import { robotsRules } from "@/lib/seo";

export default async function robots(): Promise<MetadataRoute.Robots> {
  // The site address is a deployment setting, read per request.
  await connection();
  return robotsRules();
}

import { headers } from "next/headers";

import { jsonLdText } from "@/lib/seo";

/** Structured data for search engines. A data block, never run as script. */
export async function JsonLd({ data }: { data: unknown }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return <script type="application/ld+json" nonce={nonce} dangerouslySetInnerHTML={{ __html: jsonLdText(data) }} />;
}

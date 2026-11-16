import type { Metadata } from "next";

import { IntelLookup } from "@/components/community/intel-lookup";

export const metadata: Metadata = { title: "Threat intelligence" };

export default function IntelligencePage() {
  return (
    <div className="mx-auto max-w-4xl space-y-8 px-4 py-12 sm:px-6 sm:py-16">
      <div className="space-y-3">
        <h1 className="font-display text-title font-bold text-ink sm:text-[2.25rem]">Threat intelligence lookup</h1>
        <p className="text-ink-muted">
          Check whether a domain, IP address or file fingerprint appears in the threat feeds SENTINEL
          uses, or in community reports a moderator has confirmed. For a full check of a link, use the{" "}
          <a href="/scan?type=url" className="text-accent underline underline-offset-4">link scanner</a>.
        </p>
      </div>
      <IntelLookup />
    </div>
  );
}

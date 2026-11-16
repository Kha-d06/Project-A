import type { Metadata } from "next";

import { IntelLookup } from "@/components/community/intel-lookup";
import { PageTitle } from "@/components/dashboard/dashboard-shell";

export const metadata: Metadata = { title: "Threat intelligence" };

export default function DashboardIntelligencePage() {
  return (
    <div className="max-w-4xl">
      <PageTitle title="Threat intelligence" description="Look up a domain, IP address or file fingerprint." />
      <IntelLookup />
    </div>
  );
}

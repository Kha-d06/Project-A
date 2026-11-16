import type { Metadata } from "next";

import { IntelLookup } from "@/components/community/intel-lookup";
import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Threat intelligence" };

export default async function DashboardIntelligencePage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="max-w-4xl">
      <PageTitle title={t.dashboard.nav.intelligence} description={t.intel.intro} />
      <IntelLookup />
    </div>
  );
}

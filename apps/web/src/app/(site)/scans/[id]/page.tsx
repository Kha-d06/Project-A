import type { Metadata } from "next";

import { ScanReport } from "@/components/scan/scan-report";

export const metadata: Metadata = { title: "Scan report", robots: { index: false } };

export default async function PublicReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <ScanReport scanId={id} backHref="/scan" newScanHref="/scan" />
    </div>
  );
}

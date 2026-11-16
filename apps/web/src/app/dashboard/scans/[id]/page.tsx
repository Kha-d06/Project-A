import type { Metadata } from "next";

import { ScanReport } from "@/components/scan/scan-report";

export const metadata: Metadata = { title: "Scan report" };

export default async function DashboardReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <ScanReport scanId={id} backHref="/dashboard/history" newScanHref="/dashboard/scan" />;
}

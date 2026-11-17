import type { Metadata } from "next";

import { AssessmentReport } from "@/components/dashboard/assessment-report";

export const metadata: Metadata = { title: "Assessment report" };

export default async function AssessmentReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <AssessmentReport id={id} />;
}

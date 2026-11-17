import type { Metadata } from "next";

import { SecurityAssessment } from "@/components/dashboard/security-assessment";

export const metadata: Metadata = { title: "Website security assessment" };

export default function AssessmentPage() {
  return <SecurityAssessment />;
}

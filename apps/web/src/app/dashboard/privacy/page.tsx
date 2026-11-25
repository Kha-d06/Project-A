import type { Metadata } from "next";

import { PrivacyTools } from "@/components/dashboard/privacy-tools";

export const metadata: Metadata = { title: "Privacy" };

export default function PrivacyPage() {
  return <PrivacyTools />;
}

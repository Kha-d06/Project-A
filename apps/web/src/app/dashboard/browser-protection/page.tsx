import type { Metadata } from "next";

import { BrowserProtection } from "@/components/dashboard/browser-protection";

export const metadata: Metadata = { title: "Browser protection" };

export default function BrowserProtectionPage() {
  return <BrowserProtection />;
}

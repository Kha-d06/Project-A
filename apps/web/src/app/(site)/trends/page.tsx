import type { Metadata } from "next";

import { TrendsView } from "@/components/site/trends";

export const metadata: Metadata = {
  title: "Scam trends",
  description: "Which scams SENTINEL has been seeing recently. Aggregate counts only.",
};

export default function TrendsPage() {
  return <TrendsView />;
}

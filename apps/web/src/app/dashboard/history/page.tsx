import type { Metadata } from "next";

import { History } from "@/components/dashboard/history";

export const metadata: Metadata = { title: "Scan history" };

export default function HistoryPage() {
  return <History />;
}

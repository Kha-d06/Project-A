import type { Metadata } from "next";

import { SharedReport } from "@/components/scan/shared-report";

export const metadata: Metadata = { title: "Shared result", robots: { index: false } };

export default async function SharedResultPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <SharedReport token={token} />
    </div>
  );
}

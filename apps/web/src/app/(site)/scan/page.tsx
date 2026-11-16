import type { Metadata } from "next";
import { Suspense } from "react";

import { ScanCenter } from "@/components/scan/scan-center";

export const metadata: Metadata = { title: "Scan something" };

export default function ScanPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 px-4 py-12 sm:px-6 sm:py-16">
      <div className="space-y-3">
        <h1 className="font-display text-title font-bold text-ink sm:text-[2.25rem]">
          What would you like to check?
        </h1>
        <p className="text-ink-muted">
          No account needed. Results for scans made without signing in are available from their
          link for 30 days, then deleted.
        </p>
      </div>
      <Suspense>
        <ScanCenter reportBase="/scans" />
      </Suspense>
    </div>
  );
}

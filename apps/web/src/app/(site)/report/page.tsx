import type { Metadata } from "next";

import { ReportForm } from "@/components/community/report-form";

export const metadata: Metadata = { title: "Report a scam" };

export default function ReportPage() {
  return (
    <div className="mx-auto max-w-2xl space-y-8 px-4 py-12 sm:px-6 sm:py-16">
      <div className="space-y-3">
        <h1 className="font-display text-title font-bold text-ink sm:text-[2.25rem]">Report a scam</h1>
        <p className="text-ink-muted">
          Reports help SENTINEL warn other people. A moderator reviews each one; nothing is published
          or used for warnings until it is confirmed, and reporters are never named.
        </p>
      </div>
      <ReportForm />
    </div>
  );
}

import { FileText, Link2, MessageSquareText } from "lucide-react";
import Link from "next/link";

import { RiskBadge } from "@/components/scan/risk-badge";
import type { ScanSummary, ScanType } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { SCAN_TYPE_LABEL } from "@/lib/risk";

const TYPE_ICON: Record<ScanType, typeof Link2> = {
  url: Link2,
  message: MessageSquareText,
  file: FileText,
};

export function ScanList({ scans, empty }: { scans: ScanSummary[]; empty: string }) {
  if (scans.length === 0) {
    return <p className="px-5 py-6 text-sm text-ink-muted">{empty}</p>;
  }
  return (
    <ul className="divide-y divide-line">
      {scans.map((scan) => {
        const Icon = TYPE_ICON[scan.scan_type];
        return (
          <li key={scan.id}>
            <Link
              href={`/dashboard/scans/${scan.id}`}
              className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-surface-sunken/60"
            >
              <Icon aria-label={SCAN_TYPE_LABEL[scan.scan_type]} className="size-4 shrink-0 text-ink-faint" />
              <span className="min-w-0 flex-1 truncate font-mono text-[0.8rem] text-ink" dir="auto">
                {scan.target}
              </span>
              <span className="hidden text-xs whitespace-nowrap text-ink-faint sm:inline">
                {formatRelative(scan.created_at)}
              </span>
              <RiskBadge risk={scan.risk} status={scan.status} />
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

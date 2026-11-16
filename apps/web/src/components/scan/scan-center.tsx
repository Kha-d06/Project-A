"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useRef, type KeyboardEvent } from "react";

import type { ScanType } from "@/lib/api/types";
import { cn } from "@/lib/cn";

import { ApkScanForm, FileScanForm, MessageScanForm, QrScanForm, SCAN_TABS, UrlScanForm } from "./scan-forms";

function isScanType(value: string | null): value is ScanType {
  return SCAN_TABS.some((tab) => tab.type === value);
}

/** Tabbed entry point to the three scanners. The active tab lives in the URL. */
export function ScanCenter({ reportBase }: { reportBase: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const requested = params.get("type");
  const active: ScanType = isScanType(requested) ? requested : "url";
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const select = (type: ScanType) => router.replace(`${pathname}?type=${type}`, { scroll: false });

  const onKeyDown = (event: KeyboardEvent, index: number) => {
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    event.preventDefault();
    const next = (index + step + SCAN_TABS.length) % SCAN_TABS.length;
    const tab = SCAN_TABS[next];
    if (!tab) return;
    select(tab.type);
    tabRefs.current[next]?.focus();
  };

  const activeTab = SCAN_TABS.find((tab) => tab.type === active) ?? SCAN_TABS[0]!;

  return (
    <div className="overflow-hidden rounded-panel border border-line bg-surface shadow-raised">
      <div role="tablist" aria-label="What do you want to check?" className="grid grid-cols-3 border-b border-line sm:grid-cols-6">
        {SCAN_TABS.map((tab, index) => {
          const selected = tab.type === active;
          return (
            <button
              key={tab.type}
              ref={(element) => {
                tabRefs.current[index] = element;
              }}
              role="tab"
              type="button"
              id={`tab-${tab.type}`}
              aria-selected={selected}
              aria-controls={`panel-${tab.type}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => select(tab.type)}
              onKeyDown={(event) => onKeyDown(event, index)}
              className={cn(
                "relative flex items-center justify-center gap-2 px-2 py-3.5 text-sm font-medium whitespace-nowrap transition-colors",
                selected ? "text-ink" : "text-ink-muted hover:text-ink",
              )}
            >
              <tab.icon aria-hidden className={cn("size-4", selected && "text-accent")} />
              {tab.label}
              <span
                aria-hidden
                className={cn(
                  "absolute inset-x-3 -bottom-px h-0.5 rounded-full bg-accent transition-transform duration-200",
                  selected ? "scale-x-100" : "scale-x-0",
                )}
              />
            </button>
          );
        })}
      </div>
      <div
        role="tabpanel"
        id={`panel-${active}`}
        aria-labelledby={`tab-${active}`}
        className="space-y-5 p-5 sm:p-7"
      >
        <p className="text-sm text-ink-muted">{activeTab.blurb}</p>
        {active === "url" && (
          <UrlScanForm reportBase={reportBase} initialUrl={params.get("url")?.slice(0, 2048) ?? ""} />
        )}
        {active === "message" && <MessageScanForm reportBase={reportBase} />}
        {active === "file" && <FileScanForm reportBase={reportBase} />}
        {active === "qr" && <QrScanForm reportBase={reportBase} />}
        {active === "website" && (
          <UrlScanForm reportBase={reportBase} mode="website" initialUrl={params.get("url")?.slice(0, 2048) ?? ""} />
        )}
        {active === "apk" && <ApkScanForm reportBase={reportBase} />}
      </div>
    </div>
  );
}

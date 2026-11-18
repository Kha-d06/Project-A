"use client";

import { motion } from "motion/react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useRef, type KeyboardEvent } from "react";

import type { ScanType } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";

import { ApkScanForm,
  ScreenshotScanForm, FileScanForm, MessageScanForm, QrScanForm, SCAN_TABS, UrlScanForm } from "./scan-forms";

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
  const { t, locale } = useI18n();

  const select = (type: ScanType) => router.replace(`${pathname}?type=${type}`, { scroll: false });

  const onKeyDown = (event: KeyboardEvent, index: number) => {
    // Arrow keys follow reading direction, so they are mirrored in right-to-left layouts.
    const forward = locale === "ar" ? "ArrowLeft" : "ArrowRight";
    const backward = locale === "ar" ? "ArrowRight" : "ArrowLeft";
    const step = event.key === forward ? 1 : event.key === backward ? -1 : 0;
    if (!step) return;
    event.preventDefault();
    const next = (index + step + SCAN_TABS.length) % SCAN_TABS.length;
    const tab = SCAN_TABS[next];
    if (!tab) return;
    select(tab.type);
    tabRefs.current[next]?.focus();
  };


  return (
    <div className="overflow-hidden rounded-panel border border-line bg-surface shadow-raised">
      <div
        role="tablist"
        aria-label={t.scan.tablist}
        className="flex gap-1 overflow-x-auto border-b border-line bg-surface-sunken/60 p-1.5 [scrollbar-width:none]"
      >
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
                "relative flex shrink-0 grow items-center justify-center gap-2 rounded-control px-3 py-2.5 text-sm font-medium whitespace-nowrap transition-colors",
                selected ? "text-ink" : "text-ink-muted hover:text-ink",
              )}
            >
              {selected && (
                <motion.span
                  layoutId="scan-tab"
                  aria-hidden
                  className="absolute inset-0 rounded-control border border-line-strong/70 bg-surface shadow-raised"
                  transition={{ type: "spring", stiffness: 480, damping: 38 }}
                />
              )}
              <tab.icon aria-hidden className={cn("relative size-4", selected ? "text-accent" : "text-ink-faint")} />
              <span className="relative">{t.scanTypes[tab.type]}</span>
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
        <p className="text-sm text-ink-muted">{t.scan.blurbs[active]}</p>
        {active === "url" && (
          <UrlScanForm reportBase={reportBase} initialUrl={params.get("url")?.slice(0, 2048) ?? ""} />
        )}
        {active === "message" && (
          <MessageScanForm reportBase={reportBase} initialText={params.get("text")?.slice(0, 10_000) ?? ""} />
        )}
        {active === "file" && <FileScanForm reportBase={reportBase} />}
        {active === "qr" && <QrScanForm reportBase={reportBase} />}
        {active === "website" && (
          <UrlScanForm reportBase={reportBase} mode="website" initialUrl={params.get("url")?.slice(0, 2048) ?? ""} />
        )}
        {active === "apk" && <ApkScanForm reportBase={reportBase} />}
        {active === "screenshot" && <ScreenshotScanForm reportBase={reportBase} />}
      </div>
    </div>
  );
}

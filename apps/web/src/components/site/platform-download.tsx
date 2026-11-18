"use client";

import { Download, Laptop, Monitor, Puzzle, Smartphone, Tablet, Terminal } from "lucide-react";
import Link from "next/link";
import { useSyncExternalStore } from "react";

import { ButtonLink } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";
import { type Platform, detectPlatform } from "@/lib/platform";

const subscribe = () => () => {};

function readPlatform(): Platform {
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return detectPlatform(nav.userAgent, nav.userAgentData?.platform, nav.maxTouchPoints);
}

/** The visitor's system; "unknown" while rendering on the server, so the markup matches. */
export function usePlatform(): Platform {
  return useSyncExternalStore(subscribe, readPlatform, () => "unknown");
}

/** Section anchors on /download. */
export const PLATFORM_ANCHOR: Record<Platform, string> = {
  windows: "windows",
  mac: "macos",
  linux: "linux",
  android: "android",
  ios: "iphone",
  chromeos: "extension",
  unknown: "desktop",
};

const TILES = [
  { key: "windows", anchor: "windows", icon: Monitor },
  { key: "mac", anchor: "macos", icon: Laptop },
  { key: "linux", anchor: "linux", icon: Terminal },
  { key: "android", anchor: "android", icon: Smartphone },
  { key: "ios", anchor: "iphone", icon: Tablet },
  { key: "extension", anchor: "extension", icon: Puzzle },
] as const;

/** Home page: one button for this device, and every system at a glance. */
export function DownloadPrompt() {
  const { t } = useI18n();
  const d = t.extra.download;
  const platform = usePlatform();
  const known = platform !== "unknown";
  const name = d.platformNames[platform] ?? d.platformNames.unknown!;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <ButtonLink href={known ? `/download#${PLATFORM_ANCHOR[platform]}` : "/download"} size="lg" data-platform={platform}>
          <Download aria-hidden className="size-4" />
          {known ? d.forPlatform(name) : d.allDownloads}
        </ButtonLink>
        {known && (
          <ButtonLink href="/download" variant="ghost" size="lg">
            {d.allDownloads}
          </ButtonLink>
        )}
      </div>
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" aria-label={d.otherPlatforms}>
        {TILES.map(({ key, anchor, icon: Icon }) => {
          const current = key === platform || (key === "extension" && platform === "chromeos");
          return (
            <li key={key}>
              <Link
                href={`/download#${anchor}`}
                className={cn(
                  "flex h-full items-start gap-3 rounded-panel border bg-surface p-4 transition-colors hover:border-line-strong hover:bg-surface-sunken",
                  current ? "border-accent" : "border-line",
                )}
              >
                <Icon aria-hidden className={cn("mt-0.5 size-5 shrink-0", current ? "text-accent" : "text-ink-muted")} />
                <span className="space-y-1">
                  <span className="block font-semibold text-ink">
                    {key === "extension" ? d.extension : d.platformNames[key]}
                    {current && <span className="ms-2 rounded-full bg-accent-soft px-2 py-0.5 text-xs font-medium text-accent-strong">{d.recommended}</span>}
                  </span>
                  <span className="block text-sm text-ink-muted">{d.tiles[key]}</span>
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** Header: a short link to /download, pointing at this device's section. */
export function DownloadHeaderLink({ className }: { className?: string }) {
  const { t } = useI18n();
  const platform = usePlatform();
  return (
    <ButtonLink href={platform === "unknown" ? "/download" : `/download#${PLATFORM_ANCHOR[platform]}`} variant="secondary" size="sm" className={className}>
      <Download aria-hidden className="size-3.5" />
      {t.extra.download.headerCta}
    </ButtonLink>
  );
}

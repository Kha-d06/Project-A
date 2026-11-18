"use client";

import { Download, Laptop, Puzzle } from "lucide-react";
import { type ReactNode, useEffect, useState, useSyncExternalStore } from "react";

import { PLATFORM_ANCHOR, usePlatform } from "@/components/site/platform-download";
import { ButtonLink } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { cn } from "@/lib/cn";
import { type AndroidRelease, type DesktopRelease, linuxPackages, parseAndroid, parseManifest } from "@/lib/downloads";
import { useI18n } from "@/lib/i18n/client";
import { linuxFamily } from "@/lib/platform";

interface Available {
  windows: DesktopRelease | null;
  mac: DesktopRelease | null;
  linux: DesktopRelease | null;
  android: AndroidRelease | null;
}

async function manifest(path: string): Promise<DesktopRelease | null> {
  try {
    const response = await fetch(`/downloads/desktop/${path}`, { cache: "no-store" });
    if (!response.ok) {
      await response.body?.cancel(); // an unread error page would keep the connection busy
      return null;
    }
    return parseManifest(await response.text());
  } catch {
    return null;
  }
}

async function android(): Promise<AndroidRelease | null> {
  try {
    const response = await fetch("/downloads/android/latest.json", { cache: "no-store" });
    if (!response.ok) {
      await response.body?.cancel();
      return null;
    }
    return parseAndroid(await response.json());
  } catch {
    return null;
  }
}

function FileLink({ href, label, secondary = false }: { href: string; label: string; secondary?: boolean }) {
  return (
    <a
      href={href}
      download
      className={cn(
        "inline-flex items-center gap-2 rounded-control px-4 py-2 text-sm font-medium",
        secondary ? "border border-line-strong bg-surface text-ink hover:bg-surface-sunken" : "bg-accent text-accent-ink hover:bg-accent-strong",
      )}
    >
      <Download aria-hidden className="size-4" />
      {label}
    </a>
  );
}

function Checksum({ label, value }: { label: string; value: string | null }) {
  const { t } = useI18n();
  if (!value) return null;
  return (
    <details className="text-xs text-ink-faint">
      <summary className="cursor-pointer">{t.extra.download.verify}</summary>
      <p className="mt-1 break-all font-mono" dir="ltr">
        {label}: {value}
      </p>
    </details>
  );
}

/** A platform section; highlighted when it is the visitor's own system. */
function PlatformSection({ id, title, hint, current, children }: { id: string; title: string; hint: string; current: boolean; children: ReactNode }) {
  const { t } = useI18n();
  return (
    <section id={id} aria-labelledby={`${id}-title`} className={cn("scroll-mt-24 space-y-3 rounded-panel border p-5", current ? "border-accent bg-accent-soft/40" : "border-line")}>
      <h2 id={`${id}-title`} className="flex flex-wrap items-center gap-2 font-semibold text-ink">
        {title}
        {current && <span className="rounded-full bg-accent-soft px-2 py-0.5 text-xs font-medium text-accent-strong">{t.extra.download.recommended}</span>}
      </h2>
      <p className="text-sm text-ink-muted">{hint}</p>
      {children}
    </section>
  );
}

export function DownloadView() {
  const { t } = useI18n();
  const d = t.extra.download;
  const platform = usePlatform();
  const [available, setAvailable] = useState<Available | null>(null);
  const family = useSyncExternalStore(
    () => () => {},
    () => linuxFamily(navigator.userAgent),
    () => null,
  );

  useEffect(() => {
    Promise.all([manifest("latest.yml"), manifest("latest-mac.yml"), manifest("latest-linux.yml"), android()]).then(([windows, mac, linux, apk]) =>
      setAvailable({ windows, mac, linux, android: apk }),
    );
  }, []);

  // Once the page knows the system, bring its section into view (unless a link chose one).
  useEffect(() => {
    if (!available || platform === "unknown" || window.location.hash) return;
    document.getElementById(PLATFORM_ANCHOR[platform])?.scrollIntoView({ block: "center" });
  }, [available, platform]);

  const missing = <p className="text-sm text-ink-muted">{d.notPublished}</p>;
  const base = "/downloads/desktop/";
  const name = d.platformNames[platform] ?? d.platformNames.unknown!;
  const packages = available?.linux ? linuxPackages(available.linux.version) : null;

  return (
    <div className="mx-auto max-w-5xl space-y-8 px-4 py-12 sm:px-6">
      <div className="max-w-2xl space-y-2">
        <h1 className="font-display text-display font-bold text-ink">{d.title}</h1>
        <p className="text-ink-muted">{d.description}</p>
        {platform !== "unknown" && (
          <p className="text-sm text-ink" id="detected-platform">
            {d.detected(name)}
          </p>
        )}
      </div>
      {!available ? (
        <p className="text-ink-muted">{d.loading}</p>
      ) : (
        <>
          <Panel>
            <PanelHeader title={<span className="flex items-center gap-2" id="desktop"><Laptop aria-hidden className="size-5" />{d.desktop}</span>} />
            <div className="grid gap-4 p-5 md:grid-cols-3">
              <PlatformSection id="windows" title={d.windows} hint={d.windowsHint} current={platform === "windows"}>
                {available.windows ? (
                  <>
                    <FileLink href={base + available.windows.file} label={d.version(available.windows.version)} />
                    <Checksum label={d.sha512} value={available.windows.sha512} />
                  </>
                ) : missing}
              </PlatformSection>
              <PlatformSection id="macos" title={d.mac} hint={d.macHint} current={platform === "mac"}>
                {available.mac ? (
                  <>
                    <FileLink href={base + available.mac.file} label={d.version(available.mac.version)} />
                    <Checksum label={d.sha512} value={available.mac.sha512} />
                  </>
                ) : missing}
              </PlatformSection>
              <PlatformSection id="linux" title={d.linux} hint={d.linuxHint} current={platform === "linux"}>
                {available.linux && packages ? (
                  <div className="space-y-2">
                    <div className="flex flex-wrap gap-2">
                      {/* The package for this distribution first, when the browser names it. */}
                      <FileLink href={base + packages.deb} label={d.deb} secondary={family === "rpm"} />
                      <FileLink href={base + packages.rpm} label={d.rpm} secondary={family !== "rpm"} />
                      <FileLink href={base + available.linux.file} label={d.appImage} secondary={family !== null} />
                    </div>
                    <p className="text-xs text-ink-faint">{d.version(available.linux.version)}</p>
                    <Checksum label={`${d.appImage} ${d.sha512}`} value={available.linux.sha512} />
                    <details className="text-sm">
                      <summary className="cursor-pointer text-ink">{d.linuxCommands}</summary>
                      <pre className="mt-2 overflow-x-auto rounded-control bg-surface-sunken p-3 font-mono text-xs text-ink" dir="ltr">
{`# Debian, Ubuntu, Mint
sudo apt install ./${packages.deb}
# Fedora, openSUSE, RHEL
sudo dnf install ./${packages.rpm}
# Any distribution
chmod +x ${available.linux.file} && ./${available.linux.file}`}
                      </pre>
                    </details>
                  </div>
                ) : missing}
                <div className="space-y-1 border-t border-line pt-3" id="terminal-protection">
                  <h3 className="text-sm font-semibold text-ink">{d.linuxTerminal}</h3>
                  <p className="text-sm text-ink-muted">{d.linuxTerminalHint}</p>
                  <pre className="overflow-x-auto rounded-control bg-surface-sunken p-3 font-mono text-xs text-ink" dir="ltr">
{`# after opening the app once:
qalaa terminal on
qalaa scan ~/Downloads`}
                  </pre>
                </div>
              </PlatformSection>
            </div>
          </Panel>

          <div className="grid gap-4 md:grid-cols-3">
            <PlatformSection id="android" title={d.android} hint={d.androidHint} current={platform === "android"}>
              {available.android ? (
                <>
                  <FileLink href={`/downloads/android/${available.android.file}`} label={`${d.apk} · ${d.version(available.android.version)}`} />
                  <Checksum label={d.checksum} value={available.android.sha256} />
                </>
              ) : missing}
            </PlatformSection>
            <PlatformSection id="iphone" title={d.iphone} hint={d.iphoneHint} current={platform === "ios"}>
              <ol className="list-decimal space-y-1 ps-5 text-sm text-ink">
                {d.iphoneSteps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </PlatformSection>
            <PlatformSection id="extension" title={d.extension} hint={platform === "chromeos" ? d.chromeosHint : d.extensionHint} current={platform === "chromeos"}>
              <ButtonLink href="/browser-protection" variant="secondary" size="sm">
                <Puzzle aria-hidden className="size-4" />
                {d.extensionCta}
              </ButtonLink>
            </PlatformSection>
          </div>

          {!available.windows && !available.mac && !available.linux && !available.android && <p className="text-sm text-ink-muted">{d.notPublishedHint}</p>}
          <p className="text-sm text-ink-muted">{d.afterInstall}</p>
        </>
      )}
    </div>
  );
}

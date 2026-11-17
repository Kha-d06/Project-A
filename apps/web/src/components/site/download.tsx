"use client";

import { Download, Laptop, Smartphone } from "lucide-react";
import { useEffect, useState } from "react";

import { Panel, PanelHeader } from "@/components/ui/panel";
import { type AndroidRelease, type DesktopRelease, linuxPackages, parseAndroid, parseManifest } from "@/lib/downloads";
import { useI18n } from "@/lib/i18n/client";

interface Available {
  windows: DesktopRelease | null;
  mac: DesktopRelease | null;
  linux: DesktopRelease | null;
  android: AndroidRelease | null;
}

async function manifest(path: string): Promise<DesktopRelease | null> {
  try {
    const response = await fetch(`/downloads/desktop/${path}`, { cache: "no-store" });
    return response.ok ? parseManifest(await response.text()) : null;
  } catch {
    return null;
  }
}

async function android(): Promise<AndroidRelease | null> {
  try {
    const response = await fetch("/downloads/android/latest.json", { cache: "no-store" });
    return response.ok ? parseAndroid(await response.json()) : null;
  } catch {
    return null;
  }
}

function FileLink({ href, label }: { href: string; label: string }) {
  return (
    <a href={href} download className="inline-flex items-center gap-2 rounded-control bg-accent px-4 py-2 text-sm font-medium text-accent-ink hover:bg-accent-strong">
      <Download aria-hidden className="size-4" />
      {label}
    </a>
  );
}

export function DownloadView() {
  const { t } = useI18n();
  const d = t.extra.download;
  const [available, setAvailable] = useState<Available | null>(null);

  useEffect(() => {
    Promise.all([manifest("latest.yml"), manifest("latest-mac.yml"), manifest("latest-linux.yml"), android()]).then(([windows, mac, linux, apk]) =>
      setAvailable({ windows, mac, linux, android: apk }),
    );
  }, []);

  const missing = <p className="text-sm text-ink-muted">{d.notPublished}</p>;
  const base = "/downloads/desktop/";

  return (
    <div className="mx-auto max-w-5xl space-y-8 px-4 py-12 sm:px-6">
      <div className="max-w-2xl space-y-2">
        <h1 className="font-display text-display font-bold text-ink">{d.title}</h1>
        <p className="text-ink-muted">{d.description}</p>
      </div>
      {!available ? (
        <p className="text-ink-muted">{d.loading}</p>
      ) : (
        <>
          <Panel>
            <PanelHeader title={<span className="flex items-center gap-2"><Laptop aria-hidden className="size-5" />{d.desktop}</span>} />
            <div className="grid gap-6 p-5 md:grid-cols-3">
              <section className="space-y-2" aria-labelledby="dl-windows">
                <h2 id="dl-windows" className="font-semibold text-ink">{d.windows}</h2>
                <p className="text-sm text-ink-muted">{d.windowsHint}</p>
                {available.windows ? (
                  <>
                    <FileLink href={base + available.windows.file} label={d.version(available.windows.version)} />
                  </>
                ) : missing}
              </section>
              <section className="space-y-2" aria-labelledby="dl-mac">
                <h2 id="dl-mac" className="font-semibold text-ink">{d.mac}</h2>
                <p className="text-sm text-ink-muted">{d.macHint}</p>
                {available.mac ? <FileLink href={base + available.mac.file} label={d.version(available.mac.version)} /> : missing}
              </section>
              <section className="space-y-2" aria-labelledby="dl-linux">
                <h2 id="dl-linux" className="font-semibold text-ink">{d.linux}</h2>
                <p className="text-sm text-ink-muted">{d.linuxHint}</p>
                {available.linux ? (
                  <div className="space-y-2">
                    <div className="flex flex-wrap gap-2">
                      <FileLink href={base + available.linux.file} label={d.appImage} />
                      <FileLink href={base + linuxPackages(available.linux.version).deb} label={d.deb} />
                      <FileLink href={base + linuxPackages(available.linux.version).rpm} label={d.rpm} />
                    </div>
                    <p className="text-xs text-ink-faint">{d.version(available.linux.version)}</p>
                    <details className="text-sm">
                      <summary className="cursor-pointer text-ink">{d.linuxCommands}</summary>
                      <pre className="mt-2 overflow-x-auto rounded-control bg-surface-sunken p-3 font-mono text-xs text-ink" dir="ltr">
{`# Debian, Ubuntu, Mint
sudo apt install ./${linuxPackages(available.linux.version).deb}
# Fedora, openSUSE, RHEL
sudo dnf install ./${linuxPackages(available.linux.version).rpm}
# Any distribution
chmod +x ${available.linux.file} && ./${available.linux.file}`}
                      </pre>
                    </details>
                  </div>
                ) : missing}
              </section>
            </div>
          </Panel>
          <Panel>
            <PanelHeader title={<span className="flex items-center gap-2"><Smartphone aria-hidden className="size-5" />{d.android}</span>} />
            <div className="space-y-2 p-5">
              <p className="text-sm text-ink-muted">{d.androidHint}</p>
              {available.android ? (
                <>
                  <FileLink href={`/downloads/android/${available.android.file}`} label={`${d.apk} · ${d.version(available.android.version)}`} />
                  <p className="text-xs break-all text-ink-faint" dir="ltr">{d.checksum}: {available.android.sha256}</p>
                </>
              ) : missing}
            </div>
          </Panel>
          {!available.windows && !available.mac && !available.linux && !available.android && (
            <p className="text-sm text-ink-muted">{d.notPublishedHint}</p>
          )}
          <p className="text-sm text-ink-muted">{d.afterInstall}</p>
        </>
      )}
    </div>
  );
}

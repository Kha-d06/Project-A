import {
  Eye,
  FileSearch,
  Gauge,
  Globe,
  Image as ImageIcon,
  Link2,
  Lock,
  MessageSquareWarning,
  Plus,
  QrCode,
  Scale,
  ShieldOff,
  Smartphone,
  Trash2,
} from "lucide-react";
import Link from "next/link";

import { RiskBadge } from "@/components/scan/risk-badge";
import { JsonLd } from "@/components/seo/json-ld";
import { BrowserGuardVisual } from "@/components/site/browser-guard-visual";
import { IntegrationsStatus } from "@/components/site/integrations-status";
import { DownloadPrompt } from "@/components/site/platform-download";
import { Section } from "@/components/site/section";
import { VerdictSpecimen } from "@/components/site/verdict-specimen";
import { ButtonLink } from "@/components/ui/button";
import type { RiskLevel, ScanType } from "@/lib/api/types";
import { getDictionary, getLocale } from "@/lib/i18n/server";
import { faqPageLd, softwareApplicationLd } from "@/lib/seo";

const TOOLS: { type: ScanType; icon: typeof Link2 }[] = [
  { type: "url", icon: Link2 },
  { type: "message", icon: MessageSquareWarning },
  { type: "file", icon: FileSearch },
  { type: "qr", icon: QrCode },
  { type: "website", icon: Globe },
  { type: "apk", icon: Smartphone },
  { type: "screenshot", icon: ImageIcon },
];
const VERDICTS: RiskLevel[] = ["known_malicious", "suspicious", "no_known_threat", "inconclusive"];
const PRIVACY_ICONS = [Eye, Trash2, Lock, ShieldOff];
const LIMIT_ICONS = [Gauge, FileSearch, Scale];

export default async function HomePage() {
  const t = getDictionary(await getLocale());
  const h = t.home;
  return (
    <>
      {/* The FAQ below is shown on this page, so it may be marked up. */}
      <JsonLd data={[softwareApplicationLd(), faqPageLd(h.faq)]} />
      {/* Hero: what Qalaa does, and the thing it actually hands back. */}
      <section className="mx-auto grid max-w-6xl items-center gap-12 px-4 pt-12 pb-20 sm:px-6 sm:pt-16 lg:grid-cols-12 lg:gap-8 lg:pt-24 lg:pb-28">
        <div className="min-w-0 space-y-7 lg:col-span-6">
          <h1 className="text-display font-medium text-ink">{h.title}</h1>
          <p className="max-w-xl text-lg leading-relaxed text-ink-muted sm:text-xl sm:leading-relaxed">{h.lead}</p>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <ButtonLink href="/scan" size="lg">
              {h.scan}
            </ButtonLink>
            <ButtonLink href="/browser-protection" variant="secondary" size="lg">
              {h.explore}
            </ButtonLink>
          </div>
          <p className="text-sm text-ink-faint">{h.badge}</p>
        </div>
        <div className="min-w-0 lg:col-span-6 lg:ps-6">
          <VerdictSpecimen s={h.specimen} />
        </div>
      </section>

      {/* Tools: an index, not a grid of identical cards. */}
      <Section id="product" title={h.toolsTitle} intro={h.toolsIntro}>
        <ul className="grid gap-x-12 border-t border-line sm:grid-cols-2">
          {TOOLS.map((tool) => (
            <li key={tool.type} className="border-b border-line">
              <Link href={`/scan?type=${tool.type}`} className="group flex gap-4 py-5 transition-colors duration-150 sm:py-6">
                <tool.icon aria-hidden className="mt-0.5 size-[1.125rem] shrink-0 text-ink-faint transition-colors duration-150 group-hover:text-accent" />
                <span className="space-y-1">
                  <span className="block font-medium text-ink transition-colors duration-150 group-hover:text-accent">{t.scanners[tool.type]}</span>
                  <span className="block text-[0.9375rem] leading-relaxed text-ink-muted">{h.tools[tool.type]}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      </Section>

      {/* How it works: a real sequence, so it is numbered. */}
      <Section id="how-it-works" title={h.howTitle}>
        <ol className="grid gap-10 sm:grid-cols-3 sm:gap-8">
          {h.steps.map((step, index) => (
            <li key={step.title} className="space-y-3 border-t border-line pt-5">
              <span className="tabular text-sm font-medium text-accent">{index + 1}</span>
              <h3 className="text-lg font-medium text-ink">{step.title}</h3>
              <p className="text-[0.9375rem] leading-relaxed text-ink-muted">{step.body}</p>
            </li>
          ))}
        </ol>
      </Section>

      {/* The four verdicts: Qalaa's most characteristic idea, set as a ledger. */}
      <Section id="verdicts" title={h.verdictsTitle} intro={h.verdictsIntro}>
        <div className="overflow-hidden rounded-panel border border-line bg-surface">
          {VERDICTS.map((risk, index) => (
            <div key={risk} className={"grid gap-3 px-5 py-5 sm:grid-cols-[15rem_1fr] sm:items-center sm:px-6 " + (index ? "border-t border-line" : "")}>
              <span>
                <RiskBadge risk={risk} status="completed" />
              </span>
              <p className="text-[0.9375rem] leading-relaxed text-ink-muted">{t.risk[risk].description}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* Browser protection: words beside a still of what the extension shows. */}
      <section id="browser-protection" aria-labelledby="browser-protection-title" className="scroll-mt-20 border-t border-line">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 py-20 sm:px-6 sm:py-24 lg:grid-cols-12 lg:gap-8">
          <div className="min-w-0 space-y-5 lg:col-span-5">
            <h2 id="browser-protection-title" className="text-title font-medium text-ink">
              {h.browserTitle}
            </h2>
            <p className="text-ink-muted sm:text-lg sm:leading-relaxed">{h.browserIntro}</p>
            <ButtonLink href="/browser-protection" variant="secondary">
              {h.browserCta}
            </ButtonLink>
          </div>
          <div className="min-w-0 lg:col-span-6 lg:col-start-7">
            <BrowserGuardVisual g={h.guard} />
          </div>
        </div>
      </section>

      {/* Privacy, and an honest list of limits beside it. */}
      <Section id="privacy" title={h.privacyTitle}>
        <div className="grid gap-12 lg:grid-cols-12 lg:gap-8">
          <ul className="grid gap-x-10 gap-y-9 sm:grid-cols-2 lg:col-span-7">
            {h.privacy.map((item, index) => {
              const Icon = PRIVACY_ICONS[index] ?? Eye;
              return (
                <li key={item.title} className="space-y-2">
                  <Icon aria-hidden className="size-[1.125rem] text-ink-faint" />
                  <h3 className="font-medium text-ink">{item.title}</h3>
                  <p className="text-[0.9375rem] leading-relaxed text-ink-muted">{item.body}</p>
                </li>
              );
            })}
          </ul>
          <aside className="self-start rounded-panel bg-surface-sunken p-6 lg:col-span-5">
            <h3 id="limits" className="scroll-mt-24 font-medium text-ink">
              {h.limitsTitle}
            </h3>
            <ul className="mt-4 space-y-4 text-[0.9375rem] leading-relaxed text-ink-muted">
              {h.limits.map((limit, index) => {
                const Icon = LIMIT_ICONS[index] ?? Gauge;
                return (
                  <li key={limit} className="flex gap-3">
                    <Icon aria-hidden className="mt-1 size-4 shrink-0 text-ink-faint" />
                    {limit}
                  </li>
                );
              })}
            </ul>
          </aside>
        </div>
      </Section>

      <Section id="download" title={t.extra.download.homeTitle} intro={t.extra.download.homeIntro}>
        <DownloadPrompt />
      </Section>

      <Section id="integrations" title={h.integrationsTitle} intro={h.integrationsIntro}>
        <IntegrationsStatus />
      </Section>

      <Section id="faq" title={h.faqTitle}>
        <div className="max-w-3xl divide-y divide-line border-y border-line">
          {h.faq.map((item) => (
            <details key={item.q} className="group py-5">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-6 text-lg font-medium text-ink [&::-webkit-details-marker]:hidden">
                {item.q}
                <Plus
                  aria-hidden
                  className="size-5 shrink-0 text-ink-faint transition-transform duration-200 ease-[var(--ease-out)] group-open:rotate-45"
                />
              </summary>
              <p className="mt-3 max-w-2xl animate-fade-up text-[0.9375rem] leading-relaxed text-ink-muted">{item.a}</p>
            </details>
          ))}
        </div>
      </Section>

      {/* Closing: the promise, stated once. */}
      <section className="border-t border-line bg-surface">
        <div className="mx-auto flex max-w-6xl flex-col items-start gap-6 px-4 py-20 sm:px-6 sm:py-24 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl space-y-3">
            <h2 className="text-title font-medium text-ink">{h.ctaTitle}</h2>
            <p className="text-ink-muted sm:text-lg">{h.ctaBody}</p>
          </div>
          <ButtonLink href="/scan" size="lg">
            {h.scan}
          </ButtonLink>
        </div>
      </section>
    </>
  );
}

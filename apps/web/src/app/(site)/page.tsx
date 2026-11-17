import {
  Eye,
  FileSearch,
  Gauge,
  Globe,
  Link2,
  Lock,
  MessageSquareWarning,
  QrCode,
  Scale,
  ShieldOff,
  Smartphone,
  Trash2, Image as ImageIcon } from "lucide-react";
import Link from "next/link";

import { RiskBadge } from "@/components/scan/risk-badge";
import { HeroVisual } from "@/components/site/hero-visual";
import { IntegrationsStatus } from "@/components/site/integrations-status";
import { Section } from "@/components/site/section";
import { ButtonLink } from "@/components/ui/button";
import type { RiskLevel, ScanType } from "@/lib/api/types";
import { getDictionary, getLocale } from "@/lib/i18n/server";

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
      <section className="relative overflow-hidden">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 pt-14 pb-16 sm:px-6 sm:pt-20 lg:grid-cols-[1.15fr_1fr] lg:pb-24">
          <div className="space-y-7">
            <p className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-xs text-ink-muted">
              <span aria-hidden className="size-1.5 rounded-full bg-accent" />
              {h.badge}
            </p>
            <h1 className="font-display text-[2.6rem] leading-[1.1] font-bold tracking-[-0.03em] text-ink sm:text-display">
              {h.title}
            </h1>
            <p className="max-w-xl text-lg leading-relaxed text-ink-muted">{h.lead}</p>
            <div className="flex flex-col gap-3 sm:flex-row">
              <ButtonLink href="/scan" size="lg">
                {h.scan}
              </ButtonLink>
              <ButtonLink href="/browser-protection" variant="secondary" size="lg">
                {h.explore}
              </ButtonLink>
            </div>
          </div>
          <HeroVisual />
        </div>
      </section>

      <Section id="product" eyebrow={h.toolsEyebrow} title={h.toolsTitle} intro={h.toolsIntro}>
        <ul className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {TOOLS.map((tool) => (
            <li key={tool.type}>
              <Link
                href={`/scan?type=${tool.type}`}
                className="group flex h-full gap-4 rounded-panel border border-line bg-surface p-6 transition-colors hover:border-line-strong"
              >
                <tool.icon aria-hidden className="size-5 shrink-0 text-accent" />
                <div className="space-y-2">
                  <h3 className="font-display font-semibold text-ink">{t.scanners[tool.type]}</h3>
                  <p className="text-sm leading-relaxed text-ink-muted">{h.tools[tool.type]}</p>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      </Section>

      <Section id="how-it-works" eyebrow={h.howEyebrow} title={h.howTitle}>
        <ol className="grid gap-8 md:grid-cols-3">
          {h.steps.map((step, index) => (
            <li key={step.title} className="space-y-3">
              <span className="font-mono text-sm text-accent">0{index + 1}</span>
              <h3 className="font-display text-lg font-semibold text-ink">{step.title}</h3>
              <p className="text-sm leading-relaxed text-ink-muted">{step.body}</p>
            </li>
          ))}
        </ol>
      </Section>

      <Section id="verdicts" eyebrow={h.verdictsEyebrow} title={h.verdictsTitle} intro={h.verdictsIntro}>
        <dl className="divide-y divide-line rounded-panel border border-line bg-surface">
          {VERDICTS.map((risk) => (
            <div key={risk} className="grid gap-2 px-5 py-4 sm:grid-cols-[14rem_1fr] sm:items-center">
              <dt>
                <RiskBadge risk={risk} status="completed" />
              </dt>
              <dd className="text-sm text-ink-muted">{t.risk[risk].description}</dd>
            </div>
          ))}
        </dl>
      </Section>

      <Section id="browser-protection" eyebrow={h.browserEyebrow} title={h.browserTitle} intro={h.browserIntro}>
        <ButtonLink href="/browser-protection" variant="secondary">
          {h.browserCta}
        </ButtonLink>
      </Section>

      <Section id="limits" eyebrow={h.limitsEyebrow} title={h.limitsTitle}>
        <ul className="grid gap-4 text-sm leading-relaxed text-ink-muted md:grid-cols-3">
          {h.limits.map((limit, index) => {
            const Icon = LIMIT_ICONS[index] ?? Gauge;
            return (
              <li key={limit} className="flex gap-3">
                <Icon aria-hidden className="mt-0.5 size-4 shrink-0 text-ink-faint" />
                {limit}
              </li>
            );
          })}
        </ul>
      </Section>

      <Section id="privacy" eyebrow={h.privacyEyebrow} title={h.privacyTitle}>
        <ul className="grid gap-x-8 gap-y-8 sm:grid-cols-2">
          {h.privacy.map((item, index) => {
            const Icon = PRIVACY_ICONS[index] ?? Eye;
            return (
              <li key={item.title} className="flex gap-4">
                <Icon aria-hidden className="mt-0.5 size-5 shrink-0 text-accent" />
                <div className="space-y-1">
                  <h3 className="font-medium text-ink">{item.title}</h3>
                  <p className="text-sm leading-relaxed text-ink-muted">{item.body}</p>
                </div>
              </li>
            );
          })}
        </ul>
      </Section>

      <Section id="integrations" eyebrow={h.integrationsEyebrow} title={h.integrationsTitle} intro={h.integrationsIntro}>
        <IntegrationsStatus />
      </Section>

      <Section id="faq" eyebrow={h.faqEyebrow} title={h.faqTitle}>
        <div className="divide-y divide-line rounded-panel border border-line bg-surface">
          {h.faq.map((item) => (
            <details key={item.q} className="group px-5 py-4">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-medium text-ink">
                {item.q}
                <span aria-hidden className="text-ink-faint transition-transform group-open:rotate-45">
                  +
                </span>
              </summary>
              <p className="mt-3 max-w-3xl text-sm leading-relaxed text-ink-muted">{item.a}</p>
            </details>
          ))}
        </div>
      </Section>

      <section className="border-t border-line bg-surface">
        <div className="mx-auto flex max-w-6xl flex-col items-start gap-6 px-4 py-16 sm:px-6 md:flex-row md:items-center md:justify-between">
          <div className="max-w-xl space-y-2">
            <h2 className="font-display text-title font-bold text-ink">{h.ctaTitle}</h2>
            <p className="text-ink-muted">{h.ctaBody}</p>
          </div>
          <ButtonLink href="/scan" size="lg">
            {h.scan}
          </ButtonLink>
        </div>
      </section>
    </>
  );
}

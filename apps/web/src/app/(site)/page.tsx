import {
  ArrowUpRight,
  Check,
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
import { Reveal, Stagger, StaggerItem } from "@/components/motion/reveal";
import { LogoMark } from "@/components/brand/logo";
import { BrowserGuardVisual } from "@/components/site/browser-guard-visual";
import { CitadelScene } from "@/components/site/citadel-scene";
import { InspectionPipeline } from "@/components/site/inspection-pipeline";
import { IntegrationsStatus } from "@/components/site/integrations-status";
import { DownloadPrompt } from "@/components/site/platform-download";
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
      {/* Hero */}
      <section className="relative isolate overflow-hidden">
        <div aria-hidden className="bg-survey absolute inset-0 -z-10" />
        <div aria-hidden className="glow-top absolute inset-0 -z-10" />
        <div className="mx-auto grid max-w-6xl items-center gap-10 px-4 pt-14 pb-20 sm:px-6 sm:pt-20 lg:grid-cols-[1.05fr_1fr] lg:gap-6 lg:pt-16 lg:pb-16">
          <Reveal className="space-y-8">
            <p className="inline-flex items-center gap-2.5 rounded-full border border-line-strong/70 bg-surface/70 py-1 ps-1.5 pe-3.5 text-[0.8rem] text-ink-muted shadow-raised backdrop-blur">
              <span className="relative grid size-5 place-items-center rounded-full bg-accent-soft">
                <span aria-hidden className="absolute size-2 animate-ping rounded-full bg-accent/50" />
                <span aria-hidden className="relative size-1.5 rounded-full bg-accent" />
              </span>
              {h.badge}
            </p>
            <h1 className="font-display text-display font-semibold text-balance text-ink">
              {h.title}
            </h1>
            <p className="max-w-xl text-lg leading-relaxed text-pretty text-ink-muted sm:text-xl sm:leading-relaxed">{h.lead}</p>
            <div className="flex flex-col gap-3 sm:flex-row">
              <ButtonLink href="/scan" size="lg">
                {h.scan}
                <ArrowUpRight aria-hidden className="size-4 rtl:-scale-x-100" />
              </ButtonLink>
              <ButtonLink href="/browser-protection" variant="secondary" size="lg">
                {h.explore}
              </ButtonLink>
            </div>
            <ul className="flex flex-wrap gap-x-6 gap-y-2 pt-2 text-sm text-ink-muted">
              {h.privacy.slice(0, 3).map((item) => (
                <li key={item.title} className="inline-flex items-center gap-2">
                  <Check aria-hidden className="size-4 text-oasis" />
                  {item.title}
                </li>
              ))}
            </ul>
          </Reveal>
          <Reveal delay={0.15}>
            <CitadelScene />
          </Reveal>
        </div>
      </section>

      {/* Tools */}
      <Section id="product" eyebrow={h.toolsEyebrow} title={h.toolsTitle} intro={h.toolsIntro}>
        <Stagger className="grid gap-px overflow-hidden rounded-panel border border-line bg-line md:grid-cols-2 lg:grid-cols-3">
          {TOOLS.map((tool) => (
            <StaggerItem
              key={tool.type}
              className={
                "bg-surface " +
                (tool.type === "url" ? "md:col-span-2 lg:col-span-2" : tool.type === "screenshot" ? "lg:col-span-2" : "")
              }
            >
              <Link
                href={`/scan?type=${tool.type}`}
                className="group relative flex h-full flex-col gap-5 p-7 transition-colors duration-300 hover:bg-surface-raised"
              >
                <span
                  aria-hidden
                  className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100 bg-[radial-gradient(400px_circle_at_0%_0%,var(--glow),transparent_60%)]"
                />
                <span className="relative flex items-center justify-between">
                  <span className="grid size-11 place-items-center rounded-xl border border-line-strong bg-canvas text-accent transition-transform duration-300 group-hover:-translate-y-0.5 group-hover:border-accent/40">
                    <tool.icon aria-hidden className="size-5" />
                  </span>
                  <ArrowUpRight
                    aria-hidden
                    className="size-4 text-ink-faint opacity-0 transition-all duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-accent group-hover:opacity-100 rtl:-scale-x-100"
                  />
                </span>
                <span className="relative space-y-2">
                  <h3 className={(tool.type === "url" ? "text-xl sm:text-2xl " : "text-lg ") + "font-display font-semibold tracking-[-0.015em] text-ink"}>
                    {t.scanners[tool.type]}
                  </h3>
                  <p className={(tool.type === "url" ? "max-w-lg text-[0.95rem] " : "text-sm ") + "leading-relaxed text-ink-muted"}>{h.tools[tool.type]}</p>
                </span>
              </Link>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* How it works */}
      <Section id="how-it-works" eyebrow={h.howEyebrow} title={h.howTitle} align="center">
        <InspectionPipeline steps={h.steps} />
      </Section>

      {/* Verdicts */}
      <Section id="verdicts" eyebrow={h.verdictsEyebrow} title={h.verdictsTitle} intro={h.verdictsIntro}>
        <Stagger as="div" className="overflow-hidden rounded-panel border border-line bg-surface shadow-raised">
          {VERDICTS.map((risk, index) => (
            <StaggerItem
              as="div"
              key={risk}
              className={"grid gap-3 px-6 py-5 sm:grid-cols-[15rem_1fr] sm:items-center " + (index ? "border-t border-line" : "")}
            >
              <span>
                <RiskBadge risk={risk} status="completed" />
              </span>
              <p className="text-[0.95rem] leading-relaxed text-ink-muted">{t.risk[risk].description}</p>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* Browser protection */}
      <section id="browser-protection" className="relative scroll-mt-20 overflow-hidden">
        <div aria-hidden className="absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,var(--line-strong)_20%,var(--line-strong)_80%,transparent)]" />
        <div className="mx-auto grid max-w-6xl items-center gap-14 px-4 py-20 sm:px-6 sm:py-28 lg:grid-cols-2">
          <Reveal className="space-y-5">
            <p className="flex items-center gap-3 eyebrow text-accent">
              <span aria-hidden className="h-px w-6 bg-accent/60" />
              {h.browserEyebrow}
            </p>
            <h2 className="font-display text-title font-semibold text-balance text-ink">{h.browserTitle}</h2>
            <p className="text-pretty text-ink-muted sm:text-lg sm:leading-relaxed">{h.browserIntro}</p>
            <ButtonLink href="/browser-protection" variant="secondary" className="mt-2">
              {h.browserCta}
            </ButtonLink>
          </Reveal>
          <Reveal delay={0.1}>
            <BrowserGuardVisual />
          </Reveal>
        </div>
      </section>

      {/* Privacy and limits: an editorial layout, not more cards */}
      <Section id="privacy" eyebrow={h.privacyEyebrow} title={h.privacyTitle}>
        <div className="grid gap-14 lg:grid-cols-[1.4fr_1fr]">
          <Stagger className="grid gap-x-10 gap-y-10 sm:grid-cols-2">
            {h.privacy.map((item, index) => {
              const Icon = PRIVACY_ICONS[index] ?? Eye;
              return (
                <StaggerItem key={item.title} className="space-y-3">
                  <Icon aria-hidden className="size-5 text-accent" />
                  <h3 className="font-display text-lg font-semibold tracking-[-0.01em] text-ink">{item.title}</h3>
                  <p className="text-sm leading-relaxed text-ink-muted">{item.body}</p>
                </StaggerItem>
              );
            })}
          </Stagger>
          <Reveal className="self-start rounded-panel border border-line bg-surface-sunken/50 p-7" delay={0.1}>
            <h3 id="limits" className="scroll-mt-24 eyebrow text-ink-faint">
              {h.limitsTitle}
            </h3>
            <ul className="mt-5 space-y-5 text-sm leading-relaxed text-ink-muted">
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
          </Reveal>
        </div>
      </Section>

      <Section id="download" eyebrow={t.extra.download.homeEyebrow} title={t.extra.download.homeTitle} intro={t.extra.download.homeIntro}>
        <DownloadPrompt />
      </Section>

      <Section id="integrations" eyebrow={h.integrationsEyebrow} title={h.integrationsTitle} intro={h.integrationsIntro}>
        <IntegrationsStatus />
      </Section>

      <Section id="faq" eyebrow={h.faqEyebrow} title={h.faqTitle}>
        <Stagger as="div" className="max-w-3xl divide-y divide-line border-y border-line">
          {h.faq.map((item) => (
            <StaggerItem as="div" key={item.q}>
              <details className="group py-5">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-6 font-display text-lg font-medium tracking-[-0.01em] text-ink [&::-webkit-details-marker]:hidden">
                  {item.q}
                  <span
                    aria-hidden
                    className="grid size-8 shrink-0 place-items-center rounded-full border border-line-strong text-ink-muted transition-all duration-300 group-open:rotate-45 group-open:border-accent/50 group-open:text-accent"
                  >
                    +
                  </span>
                </summary>
                <p className="mt-3 max-w-2xl animate-fade-up text-[0.95rem] leading-relaxed text-ink-muted">{item.a}</p>
              </details>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* Closing band: the citadel's watch, radar rings in brass */}
      <section className="relative isolate overflow-hidden border-t border-line bg-surface">
        <div aria-hidden className="absolute inset-0 -z-10 grid place-items-center">
          {[0, 1, 2, 3].map((ring) => (
            <span
              key={ring}
              className="absolute size-[22rem] rounded-full border border-accent/25 motion-safe:animate-[cta-ring_6s_ease-out_infinite]"
              style={{ animationDelay: `${ring * 1.5}s` }}
            />
          ))}
          <span className="absolute size-[30rem] rounded-full bg-[radial-gradient(closest-side,var(--glow),transparent)]" />
        </div>
        <Reveal className="mx-auto flex max-w-3xl flex-col items-center gap-6 px-4 py-24 text-center sm:px-6 sm:py-32">
          <span className="grid size-16 place-items-center rounded-2xl border border-line-strong bg-canvas shadow-float">
            <LogoMark className="size-9" />
          </span>
          <h2 className="font-display text-title font-semibold text-balance text-ink">{h.ctaTitle}</h2>
          <p className="max-w-xl text-pretty text-ink-muted sm:text-lg">{h.ctaBody}</p>
          <ButtonLink href="/scan" size="lg">
            {h.scan}
            <ArrowUpRight aria-hidden className="size-4 rtl:-scale-x-100" />
          </ButtonLink>
        </Reveal>
        <style>{`@keyframes cta-ring { from { transform: scale(.4); opacity: 0; } 20% { opacity: 1; } to { transform: scale(1.6); opacity: 0; } }`}</style>
      </section>
    </>
  );
}

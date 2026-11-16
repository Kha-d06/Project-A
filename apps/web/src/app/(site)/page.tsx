import {
  Eye,
  FileSearch,
  Globe,
  Smartphone,
  Gauge,
  Link2,
  Lock,
  MessageSquareWarning,
  QrCode,
  Scale,
  ShieldOff,
  Trash2,
} from "lucide-react";

import { RiskBadge } from "@/components/scan/risk-badge";
import { HeroVisual } from "@/components/site/hero-visual";
import { IntegrationsStatus } from "@/components/site/integrations-status";
import { Section } from "@/components/site/section";
import { ButtonLink } from "@/components/ui/button";
import { RISK } from "@/lib/risk";
import type { RiskLevel } from "@/lib/api/types";

const TOOLS = [
  {
    icon: Link2,
    title: "Link scanner",
    href: "/scan?type=url",
    body: "Checks a link against malware feeds, follows its redirects from our server, reads the certificate and registration date, and looks for look-alike domains.",
  },
  {
    icon: MessageSquareWarning,
    title: "Message scanner",
    href: "/scan?type=message",
    body: "Recognises the wording of delivery, prize, job, investment and account-suspension scams in English and Arabic, and pulls out the links and numbers inside.",
  },
  {
    icon: FileSearch,
    title: "File scanner",
    href: "/scan?type=file",
    body: "Identifies what a file really is, spots disguised programs, macros, risky scripts and archive tricks, and checks its fingerprint against known malware.",
  },
  {
    icon: QrCode,
    title: "QR code scanner",
    href: "/scan?type=qr",
    body: "Reads a QR code from a photo and checks where it leads, without opening it. Payment codes show who you would be paying.",
  },
  {
    icon: Globe,
    title: "Website analyzer",
    href: "/scan?type=website",
    body: "Reads a page as text, never running its scripts, to spot fake sign-in forms, brand imitation, hidden frames and obfuscated code, and looks up its DNS.",
  },
  {
    icon: Smartphone,
    title: "Android app analyzer",
    href: "/scan?type=apk",
    body: "Inspects an APK without installing it: risky permission combinations, fake versions of popular apps, embedded addresses and known malware.",
  },
];

const STEPS = [
  {
    title: "You submit something",
    body: "A link, a message or a file. No account is needed. If you are signed in, the result is saved to your private history.",
  },
  {
    title: "SENTINEL runs real checks",
    body: "Threat feeds, redirect tracing, registry lookups and static file inspection, each from our server. Your device never opens the item.",
  },
  {
    title: "You get a plain answer with evidence",
    body: "A verdict, the specific reasons behind it, every check that ran or could not, and what to do next.",
  },
];

const VERDICTS: RiskLevel[] = ["known_malicious", "suspicious", "no_known_threat", "inconclusive"];

const PRIVACY = [
  {
    icon: Eye,
    title: "Local threat matching",
    body: "Links and file fingerprints are compared against threat feeds stored on our server, so the item you check is not handed to another company.",
  },
  {
    icon: Trash2,
    title: "Samples are deleted",
    body: "Uploaded files are deleted as soon as the scan finishes. Message text is discarded after analysis.",
  },
  {
    icon: Lock,
    title: "No account required",
    body: "Every scanner works without signing up. An account only adds history, which you can switch off, export or delete.",
  },
  {
    icon: ShieldOff,
    title: "No tracking",
    body: "No advertising, no analytics scripts, no third-party fonts. The pages load from this server only.",
  },
];

const FAQ = [
  {
    q: "If SENTINEL finds nothing, is the link safe?",
    a: "Not necessarily. “No known threat detected” means none of our checks found a known problem. New phishing sites often go unreported for hours or days. Keep checking the address bar and be wary of any request for passwords, codes or money.",
  },
  {
    q: "Why would a result be inconclusive?",
    a: "A verdict that something has no known threats depends on at least one reputation source working. If the threat feed is out of date or a service is down, we say so instead of guessing.",
  },
  {
    q: "Does SENTINEL open the link or run the file?",
    a: "No. Links are followed from our server, reading only response headers, never page content, and with protections that stop it from reaching private networks. Files are inspected byte by byte and never opened or executed.",
  },
  {
    q: "Is this a replacement for antivirus software?",
    a: "No. SENTINEL is a second opinion for things you are unsure about. Keep the security protection built into your device switched on.",
  },
  {
    q: "Is there a paid version?",
    a: "No. Every feature is available to everyone without payment. Limits on how many scans can be run per hour exist only to keep the service available, and they apply to everyone equally.",
  },
];

export default function HomePage() {
  return (
    <>
      <section className="relative overflow-hidden">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 pt-14 pb-16 sm:px-6 sm:pt-20 lg:grid-cols-[1.15fr_1fr] lg:pb-24">
          <div className="space-y-7">
            <p className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-xs text-ink-muted">
              <span aria-hidden className="size-1.5 rounded-full bg-accent" />
              Free for everyone. No account needed to scan.
            </p>
            <h1 className="font-display text-[2.6rem] leading-[1.05] font-bold tracking-[-0.03em] text-ink sm:text-display">
              Browse with confidence.
            </h1>
            <p className="max-w-xl text-lg leading-relaxed text-ink-muted">
              Not sure about a link, a message or a file? SENTINEL checks it against real threat
              intelligence, explains what it found in plain language, and is honest about what
              it could not check.
            </p>
            <div className="flex flex-col gap-3 sm:flex-row">
              <ButtonLink href="/scan" size="lg">
                Scan something
              </ButtonLink>
              <ButtonLink href="/browser-protection" variant="secondary" size="lg">
                Explore browser protection
              </ButtonLink>
            </div>
          </div>
          <HeroVisual />
        </div>
      </section>

      <Section
        id="product"
        eyebrow="Security tools"
        title="Check it before you trust it"
        intro="Each scanner runs real checks and shows its working, so you can see why it reached its verdict."
      >
        <ul className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {TOOLS.map((tool) => (
            <li key={tool.title}>
              <a
                href={tool.href}
                className="group flex h-full gap-4 rounded-panel border border-line bg-surface p-6 transition-colors hover:border-line-strong"
              >
                <tool.icon aria-hidden className="size-5 shrink-0 text-accent" />
                <div className="space-y-2">
                  <h3 className="font-display font-semibold text-ink">
                    {tool.title}
                  </h3>
                  <p className="text-sm leading-relaxed text-ink-muted">{tool.body}</p>
                </div>
              </a>
            </li>
          ))}
        </ul>
      </Section>

      <Section id="how-it-works" eyebrow="How it works" title="Three steps, no guesswork">
        <ol className="grid gap-8 md:grid-cols-3">
          {STEPS.map((step, index) => (
            <li key={step.title} className="space-y-3">
              <span className="font-mono text-sm text-accent">0{index + 1}</span>
              <h3 className="font-display text-lg font-semibold text-ink">{step.title}</h3>
              <p className="text-sm leading-relaxed text-ink-muted">{step.body}</p>
            </li>
          ))}
        </ol>
      </Section>

      <Section
        id="verdicts"
        eyebrow="Honest results"
        title="Four verdicts, and none of them is “safe”"
        intro="No scanner can prove that something is harmless. SENTINEL tells you exactly how far its evidence goes."
      >
        <dl className="divide-y divide-line rounded-panel border border-line bg-surface">
          {VERDICTS.map((risk) => (
            <div key={risk} className="grid gap-2 px-5 py-4 sm:grid-cols-[14rem_1fr] sm:items-center">
              <dt>
                <RiskBadge risk={risk} status="completed" />
              </dt>
              <dd className="text-sm text-ink-muted">{RISK[risk].description}</dd>
            </div>
          ))}
        </dl>
      </Section>

      <Section
        id="browser-protection"
        eyebrow="Browser protection"
        title="Warnings before a dangerous page loads"
        intro="SENTINEL Protect checks the sites you open against the same threat database and look-alike detection, warns you before known dangerous ones, pauses risky downloads, and adds “Scan link with SENTINEL” to the right-click menu. It works without an account."
      >
        <ButtonLink href="/browser-protection" variant="secondary">
          Get the extension
        </ButtonLink>
      </Section>

      <Section
        id="limits"
        eyebrow="Detection limits"
        title="What SENTINEL cannot do"
      >
        <ul className="grid gap-4 text-sm leading-relaxed text-ink-muted md:grid-cols-3">
          <li className="flex gap-3">
            <Gauge aria-hidden className="mt-0.5 size-4 shrink-0 text-ink-faint" />
            Threat feeds only know what has been reported. A brand-new phishing page can pass every
            reputation check.
          </li>
          <li className="flex gap-3">
            <FileSearch aria-hidden className="mt-0.5 size-4 shrink-0 text-ink-faint" />
            File checks are static. A program can look ordinary and still misbehave when it runs.
          </li>
          <li className="flex gap-3">
            <Scale aria-hidden className="mt-0.5 size-4 shrink-0 text-ink-faint" />
            Message analysis recognises common scam wording. Unusual or carefully written scams may
            not match.
          </li>
        </ul>
      </Section>

      <Section id="privacy" eyebrow="Privacy" title="Built to collect as little as possible">
        <ul className="grid gap-x-8 gap-y-8 sm:grid-cols-2">
          {PRIVACY.map((item) => (
            <li key={item.title} className="flex gap-4">
              <item.icon aria-hidden className="mt-0.5 size-5 shrink-0 text-accent" />
              <div className="space-y-1">
                <h3 className="font-medium text-ink">{item.title}</h3>
                <p className="text-sm leading-relaxed text-ink-muted">{item.body}</p>
              </div>
            </li>
          ))}
        </ul>
      </Section>

      <Section
        id="integrations"
        eyebrow="Integrations"
        title="What this server can check right now"
        intro="This list comes live from the scanning service. Anything not configured is skipped and reported as unavailable in your results."
      >
        <IntegrationsStatus />
      </Section>

      <Section id="faq" eyebrow="FAQ" title="Questions people ask">
        <div className="divide-y divide-line rounded-panel border border-line bg-surface">
          {FAQ.map((item) => (
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
            <h2 className="font-display text-title font-bold text-ink">
              Digital protection should be accessible to everyone. SENTINEL is free.
            </h2>
            <p className="text-ink-muted">No plans, no trials, no locked features.</p>
          </div>
          <ButtonLink href="/scan" size="lg">
            Scan something
          </ButtonLink>
        </div>
      </section>
    </>
  );
}

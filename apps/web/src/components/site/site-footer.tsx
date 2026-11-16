import Link from "next/link";

import { Logo } from "@/components/brand/logo";
import { ThemeToggle } from "@/components/site/theme-toggle";

const COLUMNS = [
  {
    title: "Tools",
    links: [
      { href: "/scan?type=url", label: "Link scanner" },
      { href: "/scan?type=message", label: "Message scanner" },
      { href: "/scan?type=file", label: "File scanner" },
      { href: "/scan?type=qr", label: "QR scanner" },
      { href: "/scan?type=website", label: "Website analyzer" },
      { href: "/scan?type=apk", label: "Android app analyzer" },
      { href: "/browser-protection", label: "Browser protection" },
      { href: "/intelligence", label: "Threat intelligence" },
      { href: "/report", label: "Report a scam" },
    ],
  },
  {
    title: "Project",
    links: [
      { href: "/about", label: "About" },
      { href: "/docs", label: "Documentation" },
      { href: "/about#contact", label: "Contact" },
    ],
  },
  {
    title: "Policies",
    links: [
      { href: "/privacy", label: "Privacy" },
      { href: "/terms", label: "Terms" },
      { href: "/about#limits", label: "Detection limits" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="border-t border-line bg-surface">
      <div className="mx-auto grid max-w-6xl gap-10 px-4 py-12 sm:px-6 md:grid-cols-[1.4fr_repeat(3,1fr)]">
        <div className="space-y-3">
          <Logo />
          <p className="max-w-xs text-sm text-ink-muted">
            Free tools for checking links, messages and files before you trust them.
          </p>
        </div>
        {COLUMNS.map((column) => (
          <div key={column.title}>
            <h2 className="text-xs font-semibold tracking-wider text-ink-faint uppercase">
              {column.title}
            </h2>
            <ul className="mt-3 space-y-2">
              {column.links.map((link) => (
                <li key={link.href}>
                  <Link href={link.href} className="text-sm text-ink-muted hover:text-ink">
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="border-t border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-5 text-sm text-ink-faint sm:px-6">
          <p>SENTINEL is free for everyone. There are no paid plans.</p>
          <ThemeToggle />
        </div>
      </div>
    </footer>
  );
}

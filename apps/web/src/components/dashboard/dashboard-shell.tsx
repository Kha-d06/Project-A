"use client";

import {
  Flag,
  Gavel,
  History,
  LayoutDashboard,
  LogOut,
  Menu,
  Puzzle,
  Radar,
  ScanSearch,
  Settings,
  ShieldCheck,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { Logo } from "@/components/brand/logo";
import { ThemeToggle } from "@/components/site/theme-toggle";
import { cn } from "@/lib/cn";
import { useSession } from "@/lib/session";

const NAV = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/scan", label: "Scan center", icon: ScanSearch },
  { href: "/dashboard/history", label: "Scan history", icon: History },
  { href: "/dashboard/browser-protection", label: "Browser protection", icon: Puzzle },
  { href: "/dashboard/intelligence", label: "Threat intelligence", icon: Radar },
  { href: "/dashboard/reports", label: "My reports", icon: Flag },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
];

// Shown only to these roles. The API enforces the same rule on every request.
const STAFF_NAV = [
  { href: "/dashboard/moderation", label: "Moderation", icon: Gavel, roles: ["moderator", "admin"] },
  { href: "/dashboard/admin", label: "Administration", icon: ShieldCheck, roles: ["admin"] },
];

const SCANNERS = [
  { href: "/dashboard/scan?type=url", label: "Link scanner" },
  { href: "/dashboard/scan?type=message", label: "Message scanner" },
  { href: "/dashboard/scan?type=file", label: "File scanner" },
  { href: "/dashboard/scan?type=qr", label: "QR scanner" },
  { href: "/dashboard/scan?type=website", label: "Website analyzer" },
  { href: "/dashboard/scan?type=apk", label: "APK analyzer" },
];

function isCurrent(pathname: string, href: string) {
  return href === "/dashboard" ? pathname === href : pathname.startsWith(href);
}

function SidebarNav() {
  const pathname = usePathname();
  const { session, signOut } = useSession();
  const router = useRouter();

  return (
    <div className="flex h-full flex-col gap-6">
      <nav aria-label="Dashboard" className="space-y-6">
        <ul className="space-y-0.5">
          {[
            ...NAV,
            ...STAFF_NAV.filter((item) => session.status === "signed-in" && item.roles.includes(session.user.role)),
          ].map((item) => {
            const current = isCurrent(pathname, item.href);
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={current ? "page" : undefined}
                  className={cn(
                    "flex items-center gap-3 rounded-control px-3 py-2 text-sm transition-colors",
                    current ? "bg-surface-sunken font-medium text-ink" : "text-ink-muted hover:bg-surface-sunken/60 hover:text-ink",
                  )}
                >
                  <item.icon aria-hidden className={cn("size-4", current && "text-accent")} />
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
        <div>
          <p className="px-3 text-xs font-semibold tracking-wider text-ink-faint uppercase">Scanners</p>
          <ul className="mt-2 space-y-0.5">
            {SCANNERS.map((item) => (
              <li key={item.href}>
                <Link href={item.href} className="block rounded-control px-3 py-1.5 text-sm text-ink-muted hover:text-ink">
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </nav>
      <div className="mt-auto space-y-3 border-t border-line pt-4">
        {session.status === "signed-in" && (
          <p className="truncate px-3 text-sm text-ink-muted" title={session.user.email}>
            {session.user.display_name ?? session.user.email}
          </p>
        )}
        <div className="flex items-center justify-between gap-2 px-1">
          <button
            type="button"
            onClick={async () => {
              await signOut();
              router.push("/");
            }}
            className="inline-flex items-center gap-2 rounded-control px-2 py-1.5 text-sm text-ink-muted hover:text-ink"
          >
            <LogOut aria-hidden className="size-4" />
            Sign out
          </button>
          <ThemeToggle />
        </div>
      </div>
    </div>
  );
}

export function DashboardShell({ children }: { children: ReactNode }) {
  const { session } = useSession();
  const router = useRouter();
  const pathname = usePathname();
  const [openOn, setOpenOn] = useState<string | null>(null);
  const menuOpen = openOn === pathname;

  useEffect(() => {
    if (session.status === "signed-out") {
      router.replace(`/sign-in?next=${encodeURIComponent(pathname)}`);
    }
  }, [session.status, router, pathname]);

  if (session.status !== "signed-in") {
    return (
      <div className="grid min-h-dvh place-items-center" role="status">
        <span className="text-sm text-ink-muted">Loading your dashboard…</span>
      </div>
    );
  }

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[15rem_1fr]">
      <aside className="sticky top-0 hidden h-dvh border-e border-line bg-surface px-3 py-5 lg:block">
        <Link href="/" aria-label="SENTINEL home" className="mb-8 block px-3">
          <Logo />
        </Link>
        <SidebarNav />
      </aside>

      <div className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-line bg-canvas/90 px-4 backdrop-blur lg:hidden">
        <Link href="/" aria-label="SENTINEL home">
          <Logo />
        </Link>
        <button
          type="button"
          aria-expanded={menuOpen}
          aria-controls="dashboard-menu"
          aria-label={menuOpen ? "Close menu" : "Open menu"}
          onClick={() => setOpenOn(menuOpen ? null : pathname)}
          className="grid size-10 place-items-center rounded-control"
        >
          {menuOpen ? <X aria-hidden className="size-5" /> : <Menu aria-hidden className="size-5" />}
        </button>
      </div>
      {menuOpen && (
        <div id="dashboard-menu" className="animate-fade-up border-b border-line bg-surface px-3 py-4 lg:hidden">
          <SidebarNav />
        </div>
      )}

      <main id="main" className="min-w-0">
        <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8 sm:py-10">{children}</div>
      </main>
    </div>
  );
}

export function PageTitle({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="space-y-1">
        <h1 className="font-display text-title font-bold text-ink">{title}</h1>
        {description && <p className="text-ink-muted">{description}</p>}
      </div>
      {action}
    </div>
  );
}

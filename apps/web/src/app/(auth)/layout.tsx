import Link from "next/link";

import { Logo } from "@/components/brand/logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="mx-auto w-full max-w-6xl px-4 py-5 sm:px-6">
        <Link href="/" aria-label="SENTINEL home" className="inline-block rounded-control">
          <Logo />
        </Link>
      </header>
      <main id="main" className="flex flex-1 items-start justify-center px-4 pt-8 pb-16 sm:pt-16">
        <div className="w-full max-w-sm">{children}</div>
      </main>
    </div>
  );
}

import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { ButtonLink } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />
      <main id="main" className="mx-auto flex w-full max-w-3xl flex-1 flex-col items-start justify-center gap-5 px-4 py-20 sm:px-6">
        <p className="font-mono text-sm text-accent">404</p>
        <h1 className="font-display text-title font-bold text-ink">This page does not exist</h1>
        <p className="text-ink-muted">The link may be mistyped, or the page may have moved.</p>
        <ButtonLink href="/">Go to the home page</ButtonLink>
      </main>
      <SiteFooter />
    </div>
  );
}

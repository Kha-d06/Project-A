import type { Metadata } from "next";

export const metadata: Metadata = { title: "Offline" };

export default function OfflinePage() {
  return (
    <main id="main" className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-4 px-6 text-center">
      <h1 className="font-display text-title font-bold text-ink">You are offline</h1>
      <p className="text-ink-muted">
        SENTINEL needs a connection to check anything: every check runs on its server. Nothing has
        been checked, so treat links and files as unverified until you are back online.
      </p>
      <p className="text-ink-muted" lang="ar" dir="rtl">
        أنت غير متصل بالإنترنت. يحتاج سنتينل إلى اتصال لفحص أي شيء، فلم يُفحص أي شيء بعد.
      </p>
    </main>
  );
}

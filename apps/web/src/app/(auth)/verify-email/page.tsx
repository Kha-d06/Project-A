import type { Metadata } from "next";
import { Suspense } from "react";

import { VerifyEmail } from "@/components/auth/account-flows";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Confirm email", robots: { index: false } };

export default async function VerifyEmailPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="space-y-8">
      <h1 className="font-display text-title font-bold text-ink">{t.account.verifyTitle}</h1>
      <Suspense>
        <VerifyEmail />
      </Suspense>
    </div>
  );
}

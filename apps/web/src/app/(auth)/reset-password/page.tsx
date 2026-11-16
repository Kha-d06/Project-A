import type { Metadata } from "next";
import { Suspense } from "react";

import { ResetPasswordForm } from "@/components/auth/account-flows";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Choose a new password", robots: { index: false } };

export default async function ResetPasswordPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="space-y-8">
      <h1 className="font-display text-title font-bold text-ink">{t.account.resetTitle}</h1>
      <Suspense>
        <ResetPasswordForm />
      </Suspense>
    </div>
  );
}

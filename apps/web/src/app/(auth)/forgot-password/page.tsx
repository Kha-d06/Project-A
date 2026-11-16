import type { Metadata } from "next";

import { ForgotPasswordForm } from "@/components/auth/account-flows";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Reset password" };

export default async function ForgotPasswordPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-display text-title font-bold text-ink">{t.account.forgotTitle}</h1>
        <p className="text-sm text-ink-muted">{t.account.forgotIntro}</p>
      </div>
      <ForgotPasswordForm />
    </div>
  );
}

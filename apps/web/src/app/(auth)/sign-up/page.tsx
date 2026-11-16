import type { Metadata } from "next";
import { Suspense } from "react";

import { AuthForm } from "@/components/auth/auth-form";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Create an account" };

export default async function SignUpPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-display text-title font-bold text-ink">{t.auth.signUpTitle}</h1>
        <p className="text-sm text-ink-muted">{t.auth.signUpIntro}</p>
      </div>
      <Suspense>
        <AuthForm mode="sign-up" />
      </Suspense>
    </div>
  );
}

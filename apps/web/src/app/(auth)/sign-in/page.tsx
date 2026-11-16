import type { Metadata } from "next";
import { Suspense } from "react";

import { AuthForm } from "@/components/auth/auth-form";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Sign in" };

export default async function SignInPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-display text-title font-bold text-ink">{t.auth.signInTitle}</h1>
        <p className="text-sm text-ink-muted">{t.auth.signInIntro}</p>
      </div>
      <Suspense>
        <AuthForm mode="sign-in" />
      </Suspense>
    </div>
  );
}

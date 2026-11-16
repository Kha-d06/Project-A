import type { Metadata } from "next";
import { Suspense } from "react";

import { AuthForm } from "@/components/auth/auth-form";

export const metadata: Metadata = { title: "Sign in" };

export default function SignInPage() {
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-display text-title font-bold text-ink">Sign in</h1>
        <p className="text-sm text-ink-muted">Your scan history and settings are waiting.</p>
      </div>
      <Suspense>
        <AuthForm mode="sign-in" />
      </Suspense>
    </div>
  );
}

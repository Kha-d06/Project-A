import type { Metadata } from "next";
import { Suspense } from "react";

import { AuthForm } from "@/components/auth/auth-form";

export const metadata: Metadata = { title: "Create an account" };

export default function SignUpPage() {
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-display text-title font-bold text-ink">Create an account</h1>
        <p className="text-sm text-ink-muted">
          Free, and optional: every scanner works without one. An account keeps a private history
          of your scans.
        </p>
      </div>
      <Suspense>
        <AuthForm mode="sign-up" />
      </Suspense>
    </div>
  );
}

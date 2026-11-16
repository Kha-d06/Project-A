"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { ApiError, api } from "@/lib/api/client";
import { useI18n } from "@/lib/i18n/client";

function errorText(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

export function ForgotPasswordForm() {
  const { t } = useI18n();
  const [email, setEmail] = useState("");
  const [state, setState] = useState<{ pending: boolean; done: boolean; error?: string }>({ pending: false, done: false });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setState({ pending: true, done: false });
    try {
      await api.auth.requestReset(email.trim());
      setState({ pending: false, done: true });
    } catch (error) {
      setState({ pending: false, done: false, error: errorText(error, t.account.failed) });
    }
  };

  if (state.done) return <Alert title={t.account.linkSent} />;
  return (
    <form onSubmit={submit} className="space-y-5">
      {state.error && <Alert tone="warning">{state.error}</Alert>}
      <Field label={t.auth.email}>
        {(props) => <Input {...props} type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />}
      </Field>
      <Button type="submit" size="lg" className="w-full" pending={state.pending}>
        {t.account.sendLink}
      </Button>
    </form>
  );
}

export function ResetPasswordForm() {
  const { t } = useI18n();
  const token = useSearchParams().get("token");
  const [password, setPassword] = useState("");
  const [state, setState] = useState<{ pending: boolean; done: boolean; error?: string }>({ pending: false, done: false });

  if (!token) return <Alert tone="warning">{t.account.missingToken}</Alert>;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setState({ pending: true, done: false });
    try {
      await api.auth.confirmReset(token, password);
      setState({ pending: false, done: true });
    } catch (error) {
      const fields = error instanceof ApiError ? error.fieldErrors() : {};
      setState({ pending: false, done: false, error: fields.new_password ?? errorText(error, t.account.failed) });
    }
  };

  if (state.done) {
    return (
      <div className="space-y-4">
        <Alert title={t.account.resetDone} />
        <Link href="/sign-in" className="font-medium text-accent underline underline-offset-4">
          {t.auth.signIn}
        </Link>
      </div>
    );
  }
  return (
    <form onSubmit={submit} className="space-y-5">
      <Field label={t.dashboard.settings.newPassword} hint={t.auth.passwordHint} error={state.error}>
        {(props) => <Input {...props} type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} />}
      </Field>
      <Button type="submit" size="lg" className="w-full" pending={state.pending} disabled={!password}>
        {t.account.resetButton}
      </Button>
    </form>
  );
}

export function VerifyEmail() {
  const { t } = useI18n();
  const token = useSearchParams().get("token");
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const started = useRef(false);

  useEffect(() => {
    // Strict mode runs effects twice in development; the token is single-use.
    if (!token || started.current) return;
    started.current = true;
    api.auth.verifyEmail(token).then(
      () => setResult({ ok: true, message: t.account.verifyDone }),
      (error: unknown) => setResult({ ok: false, message: errorText(error, t.account.failed) }),
    );
  }, [token, t.account.verifyDone, t.account.failed]);

  if (!token) return <Alert tone="warning">{t.account.missingToken}</Alert>;
  if (!result) return <p className="text-sm text-ink-muted" role="status">{t.common.loading}</p>;
  return <Alert tone={result.ok ? "info" : "warning"} title={result.message} />;
}

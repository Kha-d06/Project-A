"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { ApiError, api } from "@/lib/api/client";
import { type Dictionary } from "@/lib/i18n/en";
import { useI18n } from "@/lib/i18n/client";
import { usePasskeysSupported } from "@/lib/passkeys";
import { useSession } from "@/lib/session";

const MIN_PASSWORD_LENGTH = 10;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

type Mode = "sign-in" | "sign-up";
type Errors = Partial<Record<"email" | "password" | "display_name" | "form", string>>;

/** Only same-site paths are accepted as a post-login destination. */
export function safeNextPath(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\")
    ? next
    : "/dashboard";
}

function validate(t: Dictionary, mode: Mode, email: string, password: string): Errors {
  const errors: Errors = {};
  if (!EMAIL_PATTERN.test(email)) errors.email = t.auth.invalidEmail;
  if (!password) errors.password = t.auth.enterPassword;
  else if (mode === "sign-up" && password.length < MIN_PASSWORD_LENGTH) errors.password = t.auth.passwordShort;
  return errors;
}

export function AuthForm({ mode }: { mode: Mode }) {
  const { signIn, register, completeTwoFactor, signInWithPasskey } = useSession();
  const canPasskey = usePasskeysSupported();
  const { t } = useI18n();
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [emailEnabled, setEmailEnabled] = useState(false);

  useEffect(() => {
    if (mode !== "sign-in") return;
    api.system.providers().then(
      (providers) => setEmailEnabled((Array.isArray(providers) ? providers : []).some((p) => p.key === "email" && p.status === "active")),
      () => setEmailEnabled(false),
    );
  }, [mode]);
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [errors, setErrors] = useState<Errors>({});
  const [pending, setPending] = useState(false);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const found = validate(t, mode, email.trim(), password);
    setErrors(found);
    if (Object.keys(found).length) return;

    setPending(true);
    try {
      if (mode === "sign-in") {
        const pending = await signIn(email.trim(), password);
        if (pending) {
          setChallenge(pending.challenge);
          setPending(false);
          return;
        }
      } else await register(email.trim(), password, displayName.trim() || undefined);
      router.push(safeNextPath(params.get("next")));
    } catch (error) {
      setPending(false);
      if (error instanceof ApiError) {
        const fields = error.fieldErrors();
        setErrors(Object.keys(fields).length ? fields : { form: error.message });
      } else {
        setErrors({ form: t.auth.generic });
      }
    }
  };

  const submitCode = async (event: FormEvent) => {
    event.preventDefault();
    if (!challenge) return;
    if (!code.trim()) {
      setErrors({ form: t.account.codeMissing });
      return;
    }
    setPending(true);
    try {
      await completeTwoFactor(challenge, code.trim());
      router.push(safeNextPath(params.get("next")));
    } catch (error) {
      setPending(false);
      if (error instanceof ApiError && error.code === "challenge_expired") setChallenge(null);
      setErrors({ form: error instanceof ApiError ? error.message : t.auth.generic });
    }
  };

  if (challenge) {
    return (
      <form onSubmit={submitCode} noValidate className="space-y-5">
        <div className="space-y-1">
          <h2 className="font-display text-lg font-semibold text-ink">{t.account.codeTitle}</h2>
          <p className="text-sm text-ink-muted">{t.account.codeIntro}</p>
        </div>
        {errors.form && <Alert tone="danger">{errors.form}</Alert>}
        <Field label={t.account.code}>
          {(props) => (
            <Input
              {...props}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              value={code}
              maxLength={20}
              onChange={(event) => setCode(event.target.value)}
              className="font-mono tracking-widest"
            />
          )}
        </Field>
        <Button type="submit" size="lg" pending={pending} className="w-full">
          {t.account.verify}
        </Button>
      </form>
    );
  }

  const isSignUp = mode === "sign-up";
  return (
    <form onSubmit={onSubmit} noValidate className="space-y-5">
      {errors.form && <Alert tone="danger">{errors.form}</Alert>}
      {isSignUp && (
        <Field label={t.auth.name} error={errors.display_name}>
          {(props) => (
            <Input
              {...props}
              autoComplete="nickname"
              value={displayName}
              maxLength={80}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          )}
        </Field>
      )}
      <Field label={t.auth.email} error={errors.email}>
        {(props) => (
          <Input
            {...props}
            type="email"
            autoComplete="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        )}
      </Field>
      <Field
        label={t.auth.password}
        error={errors.password}
        hint={isSignUp ? t.auth.passwordHint : undefined}
      >
        {(props) => (
          <Input
            {...props}
            type="password"
            autoComplete={isSignUp ? "new-password" : "current-password"}
            value={password}
            maxLength={128}
            onChange={(event) => setPassword(event.target.value)}
          />
        )}
      </Field>
      <Button type="submit" size="lg" pending={pending} className="w-full">
        {isSignUp ? t.auth.createAccount : t.auth.signIn}
      </Button>
      {!isSignUp && canPasskey && (
        <Button
          type="button"
          variant="secondary"
          size="lg"
          className="w-full"
          disabled={pending}
          onClick={async () => {
            setPending(true);
            setErrors({});
            try {
              await signInWithPasskey();
              router.replace(safeNextPath(params.get("next")));
            } catch (error) {
              if (!(error instanceof DOMException && error.name === "NotAllowedError")) setErrors({ form: t.auth.passkeyFailed });
            } finally {
              setPending(false);
            }
          }}
        >
          {t.auth.signInPasskey}
        </Button>
      )}
      {!isSignUp && emailEnabled && (
        <p className="text-center text-sm">
          <Link href="/forgot-password" className="text-ink-muted underline-offset-4 hover:text-ink hover:underline">
            {t.account.forgot}
          </Link>
        </p>
      )}
      <p className="text-center text-sm text-ink-muted">
        {isSignUp ? (
          <>
            {t.auth.haveAccount}{" "}
            <Link href="/sign-in" className="font-medium text-accent hover:underline">
              {t.auth.signIn}
            </Link>
          </>
        ) : (
          <>
            {t.auth.newHere}{" "}
            <Link href="/sign-up" className="font-medium text-accent hover:underline">
              {t.auth.createLink}
            </Link>
          </>
        )}
      </p>
    </form>
  );
}

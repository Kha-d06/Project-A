"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { ApiError } from "@/lib/api/client";
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

function validate(mode: Mode, email: string, password: string): Errors {
  const errors: Errors = {};
  if (!EMAIL_PATTERN.test(email)) errors.email = "Enter a valid email address.";
  if (!password) errors.password = "Enter your password.";
  else if (mode === "sign-up" && password.length < MIN_PASSWORD_LENGTH)
    errors.password = `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  return errors;
}

export function AuthForm({ mode }: { mode: Mode }) {
  const { signIn, register } = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [errors, setErrors] = useState<Errors>({});
  const [pending, setPending] = useState(false);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const found = validate(mode, email.trim(), password);
    setErrors(found);
    if (Object.keys(found).length) return;

    setPending(true);
    try {
      if (mode === "sign-in") await signIn(email.trim(), password);
      else await register(email.trim(), password, displayName.trim() || undefined);
      router.push(safeNextPath(params.get("next")));
    } catch (error) {
      setPending(false);
      if (error instanceof ApiError) {
        const fields = error.fieldErrors();
        setErrors(Object.keys(fields).length ? fields : { form: error.message });
      } else {
        setErrors({ form: "Something went wrong. Please try again." });
      }
    }
  };

  const isSignUp = mode === "sign-up";
  return (
    <form onSubmit={onSubmit} noValidate className="space-y-5">
      {errors.form && <Alert tone="danger">{errors.form}</Alert>}
      {isSignUp && (
        <Field label="Name (optional)" error={errors.display_name}>
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
      <Field label="Email" error={errors.email}>
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
        label="Password"
        error={errors.password}
        hint={isSignUp ? `At least ${MIN_PASSWORD_LENGTH} characters. A short phrase works well.` : undefined}
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
        {isSignUp ? "Create account" : "Sign in"}
      </Button>
      <p className="text-center text-sm text-ink-muted">
        {isSignUp ? (
          <>
            Already have an account? <Link href="/sign-in" className="font-medium text-accent hover:underline">Sign in</Link>
          </>
        ) : (
          <>
            New to SENTINEL? <Link href="/sign-up" className="font-medium text-accent hover:underline">Create an account</Link>
          </>
        )}
      </p>
    </form>
  );
}

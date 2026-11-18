"use client";

import { KeyRound, Mail } from "lucide-react";
import { useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { BreachResult } from "@/lib/api/types";
import { IdentityMonitoring } from "@/components/dashboard/identity-monitoring";
import { useI18n } from "@/lib/i18n/client";
import { pwnedCount } from "@/lib/pwned";
import { useSession } from "@/lib/session";

export function BreachCheck() {
  const { t, locale } = useI18n();
  const b = t.extra.breach;
  const { session } = useSession();
  const [result, setResult] = useState<BreachResult | null>(null);
  const [emailError, setEmailError] = useState<string>();
  const [emailPending, setEmailPending] = useState(false);
  const [password, setPassword] = useState("");
  const [passwordResult, setPasswordResult] = useState<{ tone: "danger" | "info"; text: string } | null>(null);
  const [passwordPending, setPasswordPending] = useState(false);
  const email = session.status === "signed-in" ? session.user.email : "";

  const checkEmail = async () => {
    setEmailPending(true);
    setEmailError(undefined);
    try {
      setResult(await api.breach.email());
    } catch (error) {
      setEmailError(error instanceof ApiError ? error.message : String(error));
    } finally {
      setEmailPending(false);
    }
  };

  const checkPassword = async (event: FormEvent) => {
    event.preventDefault();
    if (!password) return;
    setPasswordPending(true);
    try {
      const count = await pwnedCount(password);
      setPasswordResult(
        count > 0
          ? { tone: "danger", text: b.passwordFound(count.toLocaleString(locale)) }
          : { tone: "info", text: b.passwordClear },
      );
    } catch {
      setPasswordResult({ tone: "info", text: b.passwordFailed });
    } finally {
      setPassword("");
      setPasswordPending(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageTitle title={b.title} description={b.description} />
      <Panel>
        <PanelHeader title={b.emailTitle} description={b.emailBody(email)} />
        <div className="space-y-4 p-5">
          <Button pending={emailPending} onClick={checkEmail}>
            <Mail aria-hidden className="size-4" />
            {b.emailButton}
          </Button>
          {emailError && <Alert tone="warning">{emailError}</Alert>}
          {result &&
            (result.breaches.length === 0 ? (
              <Alert tone="info">{b.noBreaches}</Alert>
            ) : (
              <Alert tone="danger" title={b.found(result.breaches.length)}>
                <ul className="mt-2 space-y-2">
                  {result.breaches.map((breach) => (
                    <li key={breach.name}>
                      <strong>{breach.title}</strong>
                      {breach.breach_date && <span className="text-ink-muted"> · {breach.breach_date}</span>}
                      <span className="block text-sm text-ink-muted">
                        {b.exposed} {breach.data_classes.join(", ")}
                      </span>
                    </li>
                  ))}
                </ul>
                <p className="mt-3">{b.emailAdvice}</p>
              </Alert>
            ))}
        </div>
      </Panel>
      <Panel>
        <PanelHeader title={b.passwordTitle} description={b.passwordBody} />
        <form onSubmit={checkPassword} className="space-y-4 p-5">
          <Field label={b.passwordLabel}>
            {(props) => (
              <Input
                {...props}
                type="password"
                autoComplete="off"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            )}
          </Field>
          <Button type="submit" pending={passwordPending}>
            <KeyRound aria-hidden className="size-4" />
            {b.passwordButton}
          </Button>
          {passwordResult && <Alert tone={passwordResult.tone}>{passwordResult.text}</Alert>}
        </form>
      </Panel>
      <IdentityMonitoring />
    </div>
  );
}

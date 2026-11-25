"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { NotificationsSection } from "@/components/dashboard/notifications";
import { PasskeysSection } from "@/components/dashboard/passkeys";
import { WebhooksSection } from "@/components/dashboard/webhooks";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { ApiKey, Profile, SecurityStatus } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";
import { useSession } from "@/lib/session";

function message(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function ProfileSection({ profile, onSaved }: { profile: Profile; onSaved: (profile: Profile) => void }) {
  const notify = useToast();
  const { updateUser } = useSession();
  const { t } = useI18n();
  const s = t.dashboard.settings;
  const [name, setName] = useState(profile.user.display_name ?? "");
  const [pending, setPending] = useState(false);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const updated = await api.user.updateSettings({ display_name: name.trim() || null });
      updateUser(updated.user);
      onSaved(updated);
      notify("success", s.profileSaved);
    } catch (error) {
      notify("error", message(error, s.profileFailed));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title={s.profile} description={s.signedInAs(profile.user.email)} />
      <form onSubmit={save} className="space-y-4 px-5 py-5">
        <Field label={s.displayName} hint={s.displayNameHint}>
          {(props) => <Input {...props} value={name} maxLength={80} onChange={(event) => setName(event.target.value)} />}
        </Field>
        <Button type="submit" variant="secondary" pending={pending}>
          {s.saveProfile}
        </Button>
      </form>
    </Panel>
  );
}

function PrivacySection({ profile, onSaved }: { profile: Profile; onSaved: (profile: Profile) => void }) {
  const notify = useToast();
  const [pending, setPending] = useState(false);
  const { t } = useI18n();
  const s = t.dashboard.settings;
  const enabled = profile.settings.save_scan_history;

  const toggle = async () => {
    setPending(true);
    try {
      onSaved(await api.user.updateSettings({ save_scan_history: !enabled }));
      notify("success", enabled ? s.historyOff : s.historyOn);
    } catch (error) {
      notify("error", message(error, s.settingFailed));
    } finally {
      setPending(false);
    }
  };

  const exportData = async () => {
    try {
      const data = await api.user.exportData();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      link.download = "sentinel-account-export.json";
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (error) {
      notify("error", message(error, s.exportFailed));
    }
  };

  return (
    <Panel>
      <PanelHeader title={s.privacy} />
      <div className="divide-y divide-line">
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <div className="max-w-lg space-y-1">
            <p id="history-label" className="font-medium text-ink">
              {s.saveHistory}
            </p>
            <p className="text-sm text-ink-muted">{s.saveHistoryHint}</p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-labelledby="history-label"
            disabled={pending}
            onClick={toggle}
            className="relative h-6 w-11 shrink-0 rounded-full border border-line-strong transition-colors aria-checked:border-accent aria-checked:bg-accent disabled:opacity-60"
          >
            <span
              aria-hidden
              className="absolute top-0.5 start-0.5 size-4.5 rounded-full bg-ink-faint transition-transform duration-200 in-aria-checked:translate-x-5 in-aria-checked:bg-accent-ink rtl:in-aria-checked:-translate-x-5"
            />
          </button>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <div className="max-w-lg space-y-1">
            <p className="font-medium text-ink">{s.export}</p>
            <p className="text-sm text-ink-muted">{s.exportHint}</p>
          </div>
          <Button variant="secondary" onClick={exportData}>
            {s.exportButton}
          </Button>
        </div>
      </div>
    </Panel>
  );
}

function PasswordSection() {
  const notify = useToast();
  const { t } = useI18n();
  const s = t.dashboard.settings;
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setErrors({});
    try {
      await api.user.changePassword({ current_password: current, new_password: next });
      setCurrent("");
      setNext("");
      notify("success", s.passwordChanged);
    } catch (error) {
      if (error instanceof ApiError && error.code === "wrong_password") setErrors({ current_password: error.message });
      else if (error instanceof ApiError && Object.keys(error.fieldErrors()).length) setErrors(error.fieldErrors());
      else notify("error", message(error, s.passwordFailed));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title={s.password} description={s.passwordDescription} />
      <form onSubmit={submit} noValidate className="grid gap-4 px-5 py-5 sm:grid-cols-2">
        <Field label={s.currentPassword} error={errors.current_password}>
          {(props) => <Input {...props} type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} />}
        </Field>
        <Field label={s.newPassword} error={errors.new_password} hint={s.newPasswordHint}>
          {(props) => <Input {...props} type="password" autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} />}
        </Field>
        <div className="sm:col-span-2">
          <Button type="submit" variant="secondary" pending={pending} disabled={!current || !next}>
            {s.changePassword}
          </Button>
        </div>
      </form>
    </Panel>
  );
}

function SecuritySection() {
  const notify = useToast();
  const { t } = useI18n();
  const a = t.account;
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [setup, setSetup] = useState<{ secret: string; qr_code: string } | null>(null);
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [disableOpen, setDisableOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    api.user.security().then(setStatus, () => setStatus(null));
  }, [reloadKey]);

  const run = async (action: () => Promise<void>) => {
    setPending(true);
    try {
      await action();
    } catch (error) {
      notify("error", message(error, a.failed));
    } finally {
      setPending(false);
    }
  };

  if (!status) return null;
  return (
    <Panel>
      <PanelHeader title={a.security} />
      <div className="divide-y divide-line">
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4 text-sm">
          {status.email_enabled ? (
            <>
              <p className="font-medium text-ink">{status.email_verified ? a.emailVerified : a.emailNotVerified}</p>
              {!status.email_verified && (
                <Button
                  size="sm"
                  variant="secondary"
                  pending={pending}
                  onClick={() => run(async () => {
                    await api.auth.resendVerification();
                    notify("success", a.resent);
                  })}
                >
                  {a.resend}
                </Button>
              )}
            </>
          ) : (
            <p className="text-ink-muted">{a.emailUnavailable}</p>
          )}
        </div>
        <div className="space-y-4 px-5 py-4 text-sm">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="max-w-lg space-y-1">
              <p className="font-medium text-ink">{status.two_factor_enabled ? a.twoFactorOn : a.twoFactorOff}</p>
              <p className="text-ink-muted">{a.twoFactorExplain}</p>
              {status.two_factor_enabled && <p className="text-ink-faint">{a.backupLeft(status.backup_codes_remaining)}</p>}
            </div>
            {status.two_factor_enabled ? (
              <Button variant="danger" size="sm" onClick={() => setDisableOpen(true)}>
                {a.turnOff}
              </Button>
            ) : (
              !setup && (
                <Button size="sm" pending={pending} onClick={() => run(async () => setSetup(await api.user.setupTwoFactor()))}>
                  {a.turnOn}
                </Button>
              )
            )}
          </div>
          {setup && !status.two_factor_enabled && (
            <form
              className="flex animate-fade-up flex-col gap-4 rounded-control border border-line p-4 sm:flex-row"
              onSubmit={(event: FormEvent) => {
                event.preventDefault();
                void run(async () => {
                  const enabled = await api.user.enableTwoFactor(code.trim());
                  setBackupCodes(enabled.backup_codes);
                  setSetup(null);
                  setCode("");
                  setReloadKey((key) => key + 1);
                });
              }}
            >
              {/* eslint-disable-next-line @next/next/no-img-element -- server-rendered data URL, not a remote image */}
              <img src={setup.qr_code} alt="QR code for your authenticator app" width={180} height={180} className="rounded-control bg-white" />
              <div className="flex-1 space-y-3">
                <p className="text-ink-muted">{a.scanQr}</p>
                <p className="text-xs text-ink-faint">
                  {a.manualKey} <code className="font-mono break-all text-ink">{setup.secret}</code>
                </p>
                <Field label={a.code}>
                  {(props) => (
                    <Input {...props} inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(event) => setCode(event.target.value)} className="w-40 font-mono tracking-widest" />
                  )}
                </Field>
                <Button type="submit" size="sm" pending={pending} disabled={code.trim().length < 6}>
                  {a.confirm}
                </Button>
              </div>
            </form>
          )}
          {backupCodes && (
            <Alert tone="warning" title={a.backupTitle}>
              <span className="block">{a.backupBody}</span>
              <ul className="mt-2 grid grid-cols-2 gap-1 font-mono text-sm text-ink sm:grid-cols-5">
                {backupCodes.map((backup) => (
                  <li key={backup}>{backup}</li>
                ))}
              </ul>
              <Button size="sm" variant="secondary" className="mt-3" onClick={() => setBackupCodes(null)}>
                {a.done}
              </Button>
            </Alert>
          )}
        </div>
      </div>
      <Dialog open={disableOpen} onClose={() => setDisableOpen(false)} title={a.turnOffTitle} description={a.turnOffBody}>
        <form
          className="space-y-4"
          onSubmit={(event: FormEvent) => {
            event.preventDefault();
            void run(async () => {
              await api.user.disableTwoFactor(password, code.trim());
              setDisableOpen(false);
              setPassword("");
              setCode("");
              setReloadKey((key) => key + 1);
            });
          }}
        >
          <Field label={t.auth.password}>
            {(props) => <Input {...props} type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />}
          </Field>
          <Field label={a.code}>
            {(props) => <Input {...props} inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} />}
          </Field>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setDisableOpen(false)}>
              {t.common.cancel}
            </Button>
            <Button type="submit" variant="danger" pending={pending} disabled={!password || !code}>
              {a.turnOff}
            </Button>
          </div>
        </form>
      </Dialog>
    </Panel>
  );
}

function ApiKeysSection() {
  const notify = useToast();
  const { t } = useI18n();
  const s = t.dashboard.settings;
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    api.user.apiKeys().then(setKeys, () => setKeys([]));
  }, [reloadKey]);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim()) return;
    setPending(true);
    try {
      setCreated((await api.user.createApiKey(name.trim())).key);
      setName("");
      setReloadKey((key) => key + 1);
    } catch (error) {
      notify("error", message(error, s.keyFailed));
    } finally {
      setPending(false);
    }
  };

  const revoke = async (key: ApiKey) => {
    try {
      await api.user.revokeApiKey(key.id);
      notify("success", s.revoked);
      setReloadKey((value) => value + 1);
    } catch (error) {
      notify("error", message(error, s.keyFailed));
    }
  };

  return (
    <Panel>
      <PanelHeader title={s.apiKeys} description={s.apiKeysDescription} />
      <div className="space-y-4 px-5 py-5">
        {created && (
          <Alert tone="warning" title={s.newKeyTitle}>
            <span className="block">{s.newKeyBody}</span>
            <span className="mt-2 flex flex-wrap items-center gap-2">
              <code className="font-mono text-xs break-all text-ink">{created}</code>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => navigator.clipboard.writeText(created).then(() => notify("success", s.copied))}
              >
                {s.copy}
              </Button>
            </span>
          </Alert>
        )}
        <form onSubmit={create} className="flex flex-wrap items-end gap-2">
          <div className="min-w-56 flex-1">
            <Field label={s.apiKeyName}>
              {(props) => (
                <Input {...props} value={name} maxLength={80} placeholder={s.apiKeyNamePlaceholder} onChange={(event) => setName(event.target.value)} />
              )}
            </Field>
          </div>
          <Button type="submit" variant="secondary" pending={pending} disabled={!name.trim()}>
            {s.createKey}
          </Button>
        </form>
        {keys?.length === 0 && <p className="text-sm text-ink-muted">{s.noKeys}</p>}
        <ul className="divide-y divide-line">
          {keys?.map((key) => (
            <li key={key.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
              <span className="font-medium text-ink">{key.name}</span>
              <code className="font-mono text-xs text-ink-faint">{key.prefix}…</code>
              <span className="text-xs text-ink-faint">
                {key.last_used_at ? s.lastUsed(formatRelative(key.last_used_at)) : s.neverUsed}
              </span>
              <Button size="sm" variant="danger" className="ms-auto" onClick={() => revoke(key)}>
                {s.revoke}
              </Button>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

function DeleteAccountSection() {
  const { clear } = useSession();
  const { t } = useI18n();
  const s = t.dashboard.settings;
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);

  const confirm = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      await api.user.deleteAccount(password);
      clear();
      router.push("/");
    } catch (caught) {
      setError(message(caught, s.deleteFailed));
      setPending(false);
    }
  };

  return (
    <Panel className="border-danger/30">
      <PanelHeader title={s.deleteAccount} />
      <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
        <p className="max-w-lg text-sm text-ink-muted">{s.deleteAccountHint}</p>
        <Button variant="danger" onClick={() => setOpen(true)}>
          {s.deleteAccount}
        </Button>
      </div>
      <Dialog
        open={open}
        onClose={() => {
          setOpen(false);
          setPassword("");
          setError(undefined);
        }}
        title={s.deleteTitle}
        description={s.deleteBody}
      >
        <form onSubmit={confirm} className="space-y-4">
          <Field label={s.password} error={error}>
            {(props) => <Input {...props} type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />}
          </Field>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)}>
              {t.common.cancel}
            </Button>
            <Button type="submit" variant="danger" pending={pending} disabled={!password}>
              {s.deleteConfirm}
            </Button>
          </div>
        </form>
      </Dialog>
    </Panel>
  );
}

export function Settings() {
  const { t } = useI18n();
  const s = t.dashboard.settings;
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.user.profile().then(setProfile, (caught: unknown) => setError(message(caught, s.loadFailed)));
  }, [s.loadFailed]);

  return (
    <div className="max-w-3xl">
      <PageTitle title={s.title} />
      {error && <Alert tone="warning">{error}</Alert>}
      {profile && (
        <div className="space-y-6">
          <ProfileSection profile={profile} onSaved={setProfile} />
          <PrivacySection profile={profile} onSaved={setProfile} />
          <NotificationsSection profile={profile} onSaved={setProfile} />
          <PasswordSection />
          <SecuritySection />
          <PasskeysSection />
          <ApiKeysSection />
          <WebhooksSection />
          <DeleteAccountSection />
        </div>
      )}
    </div>
  );
}

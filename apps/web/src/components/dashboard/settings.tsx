"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Profile } from "@/lib/api/types";
import { useSession } from "@/lib/session";

function message(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function ProfileSection({ profile, onSaved }: { profile: Profile; onSaved: (profile: Profile) => void }) {
  const notify = useToast();
  const { updateUser } = useSession();
  const [name, setName] = useState(profile.user.display_name ?? "");
  const [pending, setPending] = useState(false);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const updated = await api.user.updateSettings({ display_name: name.trim() || null });
      updateUser(updated.user);
      onSaved(updated);
      notify("success", "Profile saved.");
    } catch (error) {
      notify("error", message(error, "Your profile could not be saved."));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title="Profile" description={`Signed in as ${profile.user.email}`} />
      <form onSubmit={save} className="space-y-4 px-5 py-5">
        <Field label="Display name" hint="Shown only to you, in the dashboard.">
          {(props) => <Input {...props} value={name} maxLength={80} onChange={(event) => setName(event.target.value)} />}
        </Field>
        <Button type="submit" variant="secondary" pending={pending}>Save profile</Button>
      </form>
    </Panel>
  );
}

function PrivacySection({ profile, onSaved }: { profile: Profile; onSaved: (profile: Profile) => void }) {
  const notify = useToast();
  const [pending, setPending] = useState(false);
  const enabled = profile.settings.save_scan_history;

  const toggle = async () => {
    setPending(true);
    try {
      onSaved(await api.user.updateSettings({ save_scan_history: !enabled }));
      notify("success", enabled ? "New scans will not be saved." : "New scans will be saved to your history.");
    } catch (error) {
      notify("error", message(error, "The setting could not be changed."));
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
      notify("error", message(error, "Your data could not be exported."));
    }
  };

  return (
    <Panel>
      <PanelHeader title="Privacy and data" />
      <div className="divide-y divide-line">
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <div className="max-w-lg space-y-1">
            <p id="history-label" className="font-medium text-ink">Save scans to my history</p>
            <p className="text-sm text-ink-muted">
              When off, scans you run while signed in are handled like anonymous ones: reachable by
              their link for 30 days, then deleted. Existing history is not affected.
            </p>
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
            <p className="font-medium text-ink">Export my data</p>
            <p className="text-sm text-ink-muted">Download your account details, settings, saved scans and activity log as JSON.</p>
          </div>
          <Button variant="secondary" onClick={exportData}>Export</Button>
        </div>
      </div>
    </Panel>
  );
}

function PasswordSection() {
  const notify = useToast();
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
      notify("success", "Password changed. Other devices have been signed out.");
    } catch (error) {
      if (error instanceof ApiError && error.code === "wrong_password") setErrors({ current_password: error.message });
      else if (error instanceof ApiError && Object.keys(error.fieldErrors()).length) setErrors(error.fieldErrors());
      else notify("error", message(error, "Your password could not be changed."));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title="Password" description="Changing it signs you out everywhere else." />
      <form onSubmit={submit} noValidate className="grid gap-4 px-5 py-5 sm:grid-cols-2">
        <Field label="Current password" error={errors.current_password}>
          {(props) => <Input {...props} type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} />}
        </Field>
        <Field label="New password" error={errors.new_password} hint="At least 10 characters.">
          {(props) => <Input {...props} type="password" autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} />}
        </Field>
        <div className="sm:col-span-2">
          <Button type="submit" variant="secondary" pending={pending} disabled={!current || !next}>Change password</Button>
        </div>
      </form>
    </Panel>
  );
}

function DeleteAccountSection() {
  const { clear } = useSession();
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
      setError(message(caught, "Your account could not be deleted."));
      setPending(false);
    }
  };

  return (
    <Panel className="border-danger/30">
      <PanelHeader title="Delete account" />
      <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
        <p className="max-w-lg text-sm text-ink-muted">
          Permanently deletes your account, all saved scans and your activity log. This cannot be undone.
        </p>
        <Button variant="danger" onClick={() => setOpen(true)}>Delete account</Button>
      </div>
      <Dialog
        open={open}
        onClose={() => {
          setOpen(false);
          setPassword("");
          setError(undefined);
        }}
        title="Delete your account?"
        description="Enter your password to confirm. Your account and all its data will be removed immediately."
      >
        <form onSubmit={confirm} className="space-y-4">
          <Field label="Password" error={error}>
            {(props) => <Input {...props} type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />}
          </Field>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" variant="danger" pending={pending} disabled={!password}>Delete permanently</Button>
          </div>
        </form>
      </Dialog>
    </Panel>
  );
}

export function Settings() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.user.profile().then(setProfile, (caught: unknown) => setError(message(caught, "Settings could not be loaded.")));
  }, []);

  return (
    <div className="max-w-3xl">
      <PageTitle title="Settings" />
      {error && <Alert tone="warning">{error}</Alert>}
      {profile && (
        <div className="space-y-6">
          <ProfileSection profile={profile} onSaved={setProfile} />
          <PrivacySection profile={profile} onSaved={setProfile} />
          <PasswordSection />
          <Alert title="Email verification and password reset are not available yet">
            They need an email delivery service, which this deployment does not have configured.
            Keep your password somewhere safe, such as a password manager.
          </Alert>
          <DeleteAccountSection />
        </div>
      )}
    </div>
  );
}

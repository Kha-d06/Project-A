"use client";

import { Copy, Eye, EyeOff, ExternalLink, KeyRound, Lock, Pencil, Plus, RefreshCw, ShieldAlert, StickyNote, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Textarea } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import { useI18n } from "@/lib/i18n/client";
import { generatePassword } from "@/lib/password";
import { pwnedCount } from "@/lib/pwned";
import { useSession } from "@/lib/session";
import {
  MIN_MASTER_LENGTH,
  type StoredVault,
  type VaultDoc,
  type VaultItem,
  WrongMasterPassword,
  changeMasterPassword,
  createVault,
  decryptDoc,
  encryptDoc,
  newItem,
  unlockVault,
} from "@/lib/vault";
import { exportCsv, healthReport, importCsv, strengthLevel } from "@/lib/vault-tools";

const IDLE_LOCK_MS = 10 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 30 * 1000;

type Issue = "reused" | "weak" | "old" | "breached";

function useVaultText() {
  return useI18n().t.extra.vault;
}

function errorText(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : String(error);
}

function StrengthMeter({ password }: { password: string }) {
  const v = useVaultText();
  if (!password) return null;
  const level = strengthLevel(password);
  const tone = level === "strong" ? "bg-clear" : level === "fair" ? "bg-warning" : "bg-danger";
  const width = level === "strong" ? "w-full" : level === "fair" ? "w-2/3" : "w-1/3";
  return (
    <div className="space-y-1" aria-live="polite">
      <div className="h-1.5 rounded-full bg-surface-sunken">
        <div className={`h-1.5 rounded-full ${tone} ${width}`} />
      </div>
      <p className="text-xs text-ink-muted">{v.strength[level]}</p>
    </div>
  );
}

function siteHref(url: string): string | null {
  try {
    const parsed = new URL(url.includes("://") ? url : `https://${url}`);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : null;
  } catch {
    return null;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

// --- Create and unlock -----------------------------------------------------------

function CreateVault({ userId, onCreated }: { userId: string; onCreated: (key: CryptoKey, stored: StoredVault, doc: VaultDoc) => void }) {
  const v = useVaultText();
  const [master, setMaster] = useState("");
  const [confirm, setConfirm] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (master.length < MIN_MASTER_LENGTH) return setError(v.tooShort);
    if (strengthLevel(master) === "weak") return setError(v.tooWeak);
    if (master !== confirm) return setError(v.mismatch);
    setError(null);
    setPending(true);
    try {
      const doc: VaultDoc = { format: 1, items: [] };
      const { key, stored } = await createVault(master, userId, doc);
      const saved = await api.vault.save({ ...stored, expected_version: null });
      onCreated(key, { ...stored, version: saved.version }, doc);
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title={v.createTitle} description={v.createIntro} />
      <form onSubmit={submit} className="max-w-md space-y-4 p-5">
        <Field label={v.master} hint={v.masterHint}>
          {(props) => <Input {...props} type="password" autoComplete="new-password" required value={master} onChange={(e) => setMaster(e.target.value)} />}
        </Field>
        <StrengthMeter password={master} />
        <Field label={v.confirm} error={error ?? undefined}>
          {(props) => <Input {...props} type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />}
        </Field>
        <label className="flex items-start gap-3 text-sm">
          <input type="checkbox" className="mt-1 size-4 accent-[var(--accent)]" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} required />
          <span>{v.understand}</span>
        </label>
        <Button type="submit" pending={pending} disabled={!understood}>
          {pending ? v.creating : v.create}
        </Button>
      </form>
    </Panel>
  );
}

function UnlockVault({ stored, userId, notice, onUnlocked }: { stored: StoredVault; userId: string; notice: string | null; onUnlocked: (key: CryptoKey, doc: VaultDoc) => void }) {
  const v = useVaultText();
  const [master, setMaster] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const { key, doc } = await unlockVault(stored, master, userId);
      setMaster("");
      onUnlocked(key, doc);
    } catch (failure) {
      setError(failure instanceof WrongMasterPassword ? v.wrongMaster : errorText(failure));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader title={v.lockedTitle} />
      <form onSubmit={submit} className="max-w-md space-y-4 p-5">
        {notice && <Alert tone="info">{notice}</Alert>}
        <Field label={v.master} error={error ?? undefined}>
          {(props) => <Input {...props} type="password" autoComplete="current-password" autoFocus required value={master} onChange={(e) => setMaster(e.target.value)} />}
        </Field>
        <Button type="submit" pending={pending}>
          <Lock aria-hidden className="size-4" />
          {pending ? v.unlocking : v.unlock}
        </Button>
      </form>
    </Panel>
  );
}

// --- Item editor -----------------------------------------------------------------

function ItemEditor({ item, isNew, onSave, onClose }: { item: VaultItem; isNew: boolean; onSave: (item: VaultItem) => void; onClose: () => void }) {
  const v = useVaultText();
  const [draft, setDraft] = useState<VaultItem>(item);
  const [visible, setVisible] = useState(false);
  const set = (changes: Partial<VaultItem>) => setDraft({ ...draft, ...changes });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const now = new Date().toISOString();
    const passwordChanged = !isNew && item.password !== draft.password ? now : draft.passwordChanged;
    onSave({ ...draft, title: draft.title.trim() || hostOf(draft.url) || v.fields.title, updated: now, passwordChanged });
  };
  return (
    <Dialog open onClose={onClose} title={isNew ? (draft.kind === "note" ? v.addNote : v.addLogin) : item.title}>
      <form onSubmit={submit} className="space-y-3">
        <Field label={v.fields.title}>{(props) => <Input {...props} maxLength={200} value={draft.title} onChange={(e) => set({ title: e.target.value })} />}</Field>
        {draft.kind === "login" && (
          <>
            <Field label={v.fields.url}>{(props) => <Input {...props} dir="ltr" maxLength={2000} inputMode="url" value={draft.url} onChange={(e) => set({ url: e.target.value })} />}</Field>
            <Field label={v.fields.username}>
              {(props) => <Input {...props} dir="ltr" autoComplete="off" maxLength={500} value={draft.username} onChange={(e) => set({ username: e.target.value })} />}
            </Field>
            <Field label={v.fields.password}>
              {(props) => (
                <div className="flex gap-2">
                  <Input
                    {...props}
                    dir="ltr"
                    type={visible ? "text" : "password"}
                    autoComplete="new-password"
                    maxLength={1000}
                    className="font-mono"
                    value={draft.password}
                    onChange={(e) => set({ password: e.target.value })}
                  />
                  <Button type="button" variant="secondary" aria-label={visible ? v.hide : v.show} onClick={() => setVisible(!visible)}>
                    {visible ? <EyeOff aria-hidden className="size-4" /> : <Eye aria-hidden className="size-4" />}
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => {
                      set({ password: generatePassword({ length: 20, upper: true, digits: true, symbols: true }) });
                      setVisible(true);
                    }}
                  >
                    <RefreshCw aria-hidden className="size-4" />
                    {v.generate}
                  </Button>
                </div>
              )}
            </Field>
            <StrengthMeter password={draft.password} />
          </>
        )}
        <Field label={v.fields.notes}>{(props) => <Textarea {...props} rows={draft.kind === "note" ? 6 : 3} maxLength={10_000} value={draft.notes} onChange={(e) => set({ notes: e.target.value })} />}</Field>
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            {v.cancel}
          </Button>
          <Button type="submit">{v.save}</Button>
        </div>
      </form>
    </Dialog>
  );
}

// --- Unlocked vault --------------------------------------------------------------

function OpenVault({
  doc,
  persist,
  onLock,
  onChangeMaster,
  onDeleted,
}: {
  doc: VaultDoc;
  persist: (doc: VaultDoc) => Promise<boolean>;
  onLock: () => void;
  onChangeMaster: (master: string) => Promise<void>;
  onDeleted: () => void;
}) {
  const v = useVaultText();
  const notify = useToast();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Issue | null>(null);
  const [editing, setEditing] = useState<VaultItem | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [breached, setBreached] = useState<string[]>([]);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [newMaster, setNewMaster] = useState("");
  const [accountPassword, setAccountPassword] = useState("");
  const clipboardToken = useRef(0);

  const report = useMemo(() => healthReport(doc.items, breached), [doc.items, breached]);
  const issuesOf = useMemo(() => {
    const map = new Map<string, Issue[]>();
    const add = (id: string, issue: Issue) => map.set(id, [...(map.get(id) ?? []), issue]);
    report.reused.flat().forEach((id) => add(id, "reused"));
    report.weak.forEach((id) => add(id, "weak"));
    report.old.forEach((id) => add(id, "old"));
    report.breached.forEach((id) => add(id, "breached"));
    return map;
  }, [report]);

  const visible = doc.items
    .filter((item) => !filter || issuesOf.get(item.id)?.includes(filter))
    .filter((item) => {
      const q = query.trim().toLowerCase();
      return !q || [item.title, item.url, item.username].some((field) => field.toLowerCase().includes(q));
    })
    .sort((a, b) => a.title.localeCompare(b.title));

  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    const token = ++clipboardToken.current;
    notify("success", v.copied);
    window.setTimeout(() => {
      // Only clear if nothing else was copied from here since.
      if (token === clipboardToken.current) void navigator.clipboard.writeText("").catch(() => undefined);
    }, CLIPBOARD_CLEAR_MS);
  };

  const saveItem = async (item: VaultItem) => {
    const exists = doc.items.some((existing) => existing.id === item.id);
    const items = exists ? doc.items.map((existing) => (existing.id === item.id ? item : existing)) : [...doc.items, item];
    if (await persist({ ...doc, items })) {
      setEditing(null);
      notify("success", v.saved);
    }
  };

  const checkBreaches = async () => {
    const logins = doc.items.filter((item) => item.kind === "login" && item.password);
    const unique = [...new Set(logins.map((item) => item.password))];
    const found = new Set<string>();
    setProgress({ done: 0, total: unique.length });
    try {
      for (const [index, password] of unique.entries()) {
        if ((await pwnedCount(password)) > 0) found.add(password);
        setProgress({ done: index + 1, total: unique.length });
      }
      const ids = logins.filter((item) => found.has(item.password)).map((item) => item.id);
      setBreached(ids);
      notify(ids.length ? "error" : "success", v.breachDone(ids.length));
    } catch {
      notify("error", v.breachUnavailable);
    } finally {
      setProgress(null);
    }
  };

  const importFile = async (file: File) => {
    try {
      const { items, skipped } = importCsv(await file.text());
      if (items.length && (await persist({ ...doc, items: [...doc.items, ...items] }))) notify("success", v.imported(items.length, skipped));
    } catch (error) {
      notify("error", errorText(error));
    }
  };

  const exportFile = () => {
    if (!window.confirm(v.exportWarning)) return;
    const url = URL.createObjectURL(new Blob([exportCsv(doc.items)], { type: "text/csv" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "qalaa-passwords.csv";
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const chips: [Issue, number, string][] = [
    ["breached", report.breached.length, v.breached(report.breached.length)],
    ["reused", report.reused.flat().length, v.reused(report.reused.flat().length)],
    ["weak", report.weak.length, v.weak(report.weak.length)],
    ["old", report.old.length, v.old(report.old.length)],
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-48 flex-1">
          <Field label={v.search}>{(props) => <Input {...props} type="search" value={query} onChange={(e) => setQuery(e.target.value)} />}</Field>
        </div>
        <Button onClick={() => setEditing(newItem("login"))}>
          <Plus aria-hidden className="size-4" />
          {v.addLogin}
        </Button>
        <Button variant="secondary" onClick={() => setEditing(newItem("note"))}>
          <StickyNote aria-hidden className="size-4" />
          {v.addNote}
        </Button>
        <Button variant="secondary" onClick={onLock}>
          <Lock aria-hidden className="size-4" />
          {v.lock}
        </Button>
      </div>
      <p className="text-xs text-ink-faint">{v.autoLock}</p>

      <Panel>
        <PanelHeader title={v.health} description={v.score(report.score)} />
        <div className="space-y-3 p-5">
          <div className="flex flex-wrap gap-2">
            {chips.map(([issue, count, label]) => (
              <button
                key={issue}
                type="button"
                aria-pressed={filter === issue}
                disabled={count === 0}
                onClick={() => setFilter(filter === issue ? null : issue)}
                className={`rounded-full border px-3 py-1 text-sm disabled:opacity-50 ${
                  filter === issue ? "border-accent bg-accent-soft text-ink" : count ? "border-warning text-warning" : "border-line text-ink-muted"
                }`}
              >
                {label}
              </button>
            ))}
            {filter && (
              <button type="button" className="px-2 text-sm text-accent hover:underline" onClick={() => setFilter(null)}>
                {v.showAll}
              </button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button size="sm" variant="secondary" pending={progress !== null} onClick={checkBreaches} disabled={!doc.items.some((item) => item.password)}>
              <ShieldAlert aria-hidden className="size-4" />
              {progress ? v.checking(progress.done, progress.total) : v.checkBreaches}
            </Button>
          </div>
          <p className="text-xs text-ink-muted">{v.breachHint}</p>
        </div>
      </Panel>

      <Panel>
        {doc.items.length === 0 ? (
          <p className="p-5 text-ink-muted">{v.empty}</p>
        ) : visible.length === 0 ? (
          <p className="p-5 text-ink-muted">{v.noMatch}</p>
        ) : (
          <ul className="divide-y divide-line" id="vault-items">
            {visible.map((item) => {
              const href = item.kind === "login" ? siteHref(item.url) : null;
              const issues = issuesOf.get(item.id) ?? [];
              return (
                <li key={item.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <p className="flex flex-wrap items-center gap-2 font-medium text-ink">
                      {item.kind === "note" ? <StickyNote aria-hidden className="size-4 text-ink-muted" /> : <KeyRound aria-hidden className="size-4 text-ink-muted" />}
                      <span dir="auto">{item.title}</span>
                      {issues.map((issue) => (
                        <span key={issue} className={`rounded-full px-2 text-xs ${issue === "breached" ? "bg-danger-soft text-danger" : "bg-warning-soft text-warning"}`}>
                          {v.issues[issue]}
                        </span>
                      ))}
                    </p>
                    {item.kind === "login" && (
                      <p className="truncate text-sm text-ink-muted" dir="ltr">
                        {[item.username, item.url ? hostOf(item.url) : ""].filter(Boolean).join(" · ")}
                      </p>
                    )}
                    {revealed === item.id && (
                      <p className="mt-1 font-mono text-sm break-all text-ink" dir="ltr">
                        {item.kind === "login" ? item.password : item.notes}
                      </p>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {item.kind === "login" && item.username && (
                      <Button size="sm" variant="secondary" onClick={() => copy(item.username)} aria-label={`${v.copyUsername}: ${item.title}`}>
                        {v.copyUsername}
                      </Button>
                    )}
                    {item.kind === "login" && item.password && (
                      <Button size="sm" variant="secondary" onClick={() => copy(item.password)} aria-label={`${v.copyPassword}: ${item.title}`}>
                        <Copy aria-hidden className="size-4" />
                        {v.copyPassword}
                      </Button>
                    )}
                    <Button size="sm" variant="secondary" aria-label={`${revealed === item.id ? v.hide : v.show}: ${item.title}`} onClick={() => setRevealed(revealed === item.id ? null : item.id)}>
                      {revealed === item.id ? <EyeOff aria-hidden className="size-4" /> : <Eye aria-hidden className="size-4" />}
                    </Button>
                    {href && (
                      <a
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center rounded-control border border-line px-2 text-ink-muted hover:text-ink"
                        aria-label={`${v.openSite}: ${item.title}`}
                      >
                        <ExternalLink aria-hidden className="size-4" />
                      </a>
                    )}
                    <Button size="sm" variant="secondary" aria-label={`${v.edit}: ${item.title}`} onClick={() => setEditing(item)}>
                      <Pencil aria-hidden className="size-4" />
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      aria-label={`${v.delete}: ${item.title}`}
                      onClick={async () => {
                        if (window.confirm(v.confirmDelete(item.title))) await persist({ ...doc, items: doc.items.filter((other) => other.id !== item.id) });
                      }}
                    >
                      <Trash2 aria-hidden className="size-4" />
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <details className="rounded-panel border border-line bg-surface">
        <summary className="cursor-pointer px-5 py-4 font-semibold text-ink">{v.manage}</summary>
        <div className="grid gap-6 border-t border-line p-5 lg:grid-cols-2">
          <div className="space-y-2">
            <Field label={v.importLabel} hint={v.importHint}>
              {(props) => (
                <input
                  {...props}
                  type="file"
                  accept=".csv,text/csv"
                  className="block text-sm"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) void importFile(file);
                    e.target.value = "";
                  }}
                />
              )}
            </Field>
            <Button size="sm" variant="secondary" onClick={exportFile} disabled={!doc.items.length}>
              {v.exportLabel}
            </Button>
          </div>
          <form
            className="space-y-2"
            onSubmit={async (event) => {
              event.preventDefault();
              if (newMaster.length < MIN_MASTER_LENGTH) return notify("error", v.tooShort);
              if (strengthLevel(newMaster) === "weak") return notify("error", v.tooWeak);
              await onChangeMaster(newMaster);
              setNewMaster("");
            }}
          >
            <Field label={v.newMaster}>
              {(props) => <Input {...props} type="password" autoComplete="new-password" value={newMaster} onChange={(e) => setNewMaster(e.target.value)} />}
            </Field>
            <StrengthMeter password={newMaster} />
            <Button size="sm" type="submit" variant="secondary" disabled={!newMaster}>
              {v.changeMaster}
            </Button>
          </form>
          <form
            className="space-y-2 lg:col-span-2"
            onSubmit={async (event) => {
              event.preventDefault();
              try {
                await api.vault.remove(accountPassword);
                notify("success", v.deleted);
                onDeleted();
              } catch (error) {
                notify("error", errorText(error));
              }
            }}
          >
            <Field label={v.accountPassword} hint={v.deleteHint}>
              {(props) => <Input {...props} type="password" autoComplete="current-password" value={accountPassword} onChange={(e) => setAccountPassword(e.target.value)} />}
            </Field>
            <Button size="sm" type="submit" variant="danger" disabled={!accountPassword}>
              <Trash2 aria-hidden className="size-4" />
              {v.deleteVault}
            </Button>
          </form>
        </div>
      </details>

      {editing && <ItemEditor key={editing.id} item={editing} isNew={!doc.items.some((i) => i.id === editing.id)} onSave={saveItem} onClose={() => setEditing(null)} />}
    </div>
  );
}

// --- Page ------------------------------------------------------------------------

async function fetchVault(): Promise<StoredVault | null> {
  try {
    return await api.vault.get();
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

type Phase = { name: "loading" } | { name: "none" } | { name: "locked"; notice: string | null } | { name: "open" };

export function PasswordVault() {
  const v = useVaultText();
  const notify = useToast();
  const { session } = useSession();
  const userId = session.status === "signed-in" ? session.user.id : "";
  const [phase, setPhase] = useState<Phase>({ name: "loading" });
  const [stored, setStored] = useState<StoredVault | null>(null);
  const [doc, setDoc] = useState<VaultDoc | null>(null);
  // Held only in memory, as a non-extractable key, while the vault is open.
  const key = useRef<CryptoKey | null>(null);

  const lock = useCallback((notice: string | null = null) => {
    key.current = null;
    setDoc(null);
    setPhase({ name: "locked", notice });
  }, []);

  const load = useCallback(async () => {
    const vault = await fetchVault();
    setStored(vault);
    if (!vault) setPhase({ name: "none" });
    return vault;
  }, []);

  useEffect(() => {
    fetchVault()
      .then((vault) => {
        setStored(vault);
        setPhase(vault ? { name: "locked", notice: null } : { name: "none" });
      })
      .catch((error) => notify("error", errorText(error)));
  }, [notify]);

  // Lock after a period without activity, and when the account signs out.
  useEffect(() => {
    if (phase.name !== "open") return;
    let timer = window.setTimeout(() => lock(), IDLE_LOCK_MS);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => lock(), IDLE_LOCK_MS);
    };
    const events = ["pointerdown", "keydown", "scroll"] as const;
    events.forEach((name) => window.addEventListener(name, reset, { passive: true }));
    return () => {
      window.clearTimeout(timer);
      events.forEach((name) => window.removeEventListener(name, reset));
    };
  }, [phase.name, lock]);

  const persist = async (next: VaultDoc): Promise<boolean> => {
    if (!key.current || !stored) return false;
    try {
      const data = await encryptDoc(key.current, next, userId);
      const saved = await api.vault.save({ kdf: stored.kdf, wrapped_key: stored.wrapped_key, data, expected_version: stored.version });
      setStored({ ...stored, data, version: saved.version });
      setDoc(next);
      return true;
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        // Changed elsewhere: reload. Same key unless the master password changed there too.
        const fresh = await load();
        if (!fresh) return false;
        if (fresh.wrapped_key !== stored.wrapped_key) {
          lock(v.lockedElsewhere);
        } else {
          setDoc(await decryptDoc(key.current, fresh.data, userId));
          notify("error", v.conflict);
        }
        return false;
      }
      notify("error", errorText(error));
      return false;
    }
  };

  const changeMaster = async (master: string) => {
    if (!doc || !stored) return;
    try {
      const fresh = await changeMasterPassword(master, userId, doc);
      const saved = await api.vault.save({ ...fresh.stored, expected_version: stored.version });
      key.current = fresh.key;
      setStored({ ...fresh.stored, version: saved.version });
      notify("success", v.changed);
    } catch (error) {
      notify("error", errorText(error));
    }
  };

  return (
    <div className="space-y-6">
      <PageTitle title={v.title} description={v.description} />
      {phase.name === "none" && userId && (
        <CreateVault
          userId={userId}
          onCreated={(created, vault, fresh) => {
            key.current = created;
            setStored(vault);
            setDoc(fresh);
            setPhase({ name: "open" });
          }}
        />
      )}
      {phase.name === "locked" && stored && userId && (
        <UnlockVault
          stored={stored}
          userId={userId}
          notice={phase.notice}
          onUnlocked={(unlocked, opened) => {
            key.current = unlocked;
            setDoc(opened);
            setPhase({ name: "open" });
          }}
        />
      )}
      {phase.name === "open" && doc && (
        <OpenVault
          doc={doc}
          persist={persist}
          onLock={() => lock()}
          onChangeMaster={changeMaster}
          onDeleted={() => {
            key.current = null;
            setDoc(null);
            setStored(null);
            setPhase({ name: "none" });
          }}
        />
      )}
    </div>
  );
}

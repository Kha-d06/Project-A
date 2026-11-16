"use client";

import { Plus, Trash2, UserPlus } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { RiskBadge } from "@/components/scan/risk-badge";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { Group, GroupKind, GroupSharedScan } from "@/lib/api/types";
import { formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";
import { useSession } from "@/lib/session";

function errorText(error: unknown): string {
  return error instanceof ApiError ? error.message : String(error);
}

function SharedFeed({ groupId }: { groupId: string }) {
  const { t } = useI18n();
  const g = t.extra.groups;
  const [items, setItems] = useState<GroupSharedScan[] | null>(null);
  useEffect(() => {
    api.groups.shares(groupId).then(setItems).catch(() => setItems([]));
  }, [groupId]);
  if (items === null) return null;
  if (items.length === 0) return <p className="px-5 py-4 text-sm text-ink-muted">{g.noShared}</p>;
  return (
    <ul className="divide-y divide-line">
      {items.map((item) => (
        <li key={item.share_id} className="space-y-1.5 px-5 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <RiskBadge risk={item.scan.risk} status={item.scan.status} />
            <span className="text-xs text-ink-faint">{g.sharedBy(item.shared_by, formatShortDate(item.shared_at))}</span>
          </div>
          {item.scan.target && <p className="font-mono text-xs break-all text-ink" dir="auto">{item.scan.target}</p>}
          {item.note && <p className="text-sm text-ink" dir="auto">{item.note}</p>}
          {item.scan.summary && <p className="text-sm text-ink-muted" dir="auto">{item.scan.summary}</p>}
        </li>
      ))}
    </ul>
  );
}

function GroupCard({ group, myId, onChange }: { group: Group; myId: string; onChange: (group?: Group) => void }) {
  const { t } = useI18n();
  const g = t.extra.groups;
  const notify = useToast();
  const [email, setEmail] = useState("");
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const manager = group.my_role === "owner" || group.my_role === "admin";

  const run = async (action: () => Promise<Group | void>) => {
    try {
      const result = await action();
      onChange(result ?? undefined);
    } catch (error) {
      notify("error", errorText(error));
    }
  };

  const invite = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    try {
      const created = await api.groups.invite(group.id, email.trim(), "member");
      if (created.emailed) {
        notify("success", g.inviteSent(created.email));
        setInviteLink(null);
      } else {
        setInviteLink(created.url);
      }
      setEmail("");
      onChange();
    } catch (error) {
      notify("error", errorText(error));
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader
        title={group.name}
        description={`${group.kind === "family" ? g.family : g.organisation} · ${g.roles[group.my_role]}`}
        action={
          group.my_role === "owner" ? (
            <Button
              size="sm"
              variant="danger"
              onClick={() => window.confirm(g.confirmDelete) && run(() => api.groups.remove(group.id))}
            >
              <Trash2 aria-hidden className="size-4" />
              {g.deleteGroup}
            </Button>
          ) : (
            <Button size="sm" variant="secondary" onClick={() => run(() => api.groups.removeMember(group.id, myId))}>
              {g.leave}
            </Button>
          )
        }
      />
      <div className="grid gap-6 p-5 lg:grid-cols-2">
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-ink">{g.members}</h3>
          <ul className="space-y-2">
            {group.members.map((member) => (
              <li key={member.user_id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span className="min-w-0">
                  <span className="text-ink">{member.display_name ?? member.email}</span>
                  {member.user_id === myId && <span className="text-ink-faint"> ({g.you})</span>}
                  <span className="block text-xs text-ink-faint">
                    {g.roles[member.role]}
                    {manager &&
                      member.user_id !== myId &&
                      ` · ${member.warnings_last_30_days === null ? g.private : g.warnings(member.warnings_last_30_days)}`}
                  </span>
                </span>
                {manager && member.role !== "owner" && member.user_id !== myId && (
                  <span className="flex gap-2">
                    <button
                      type="button"
                      className="text-xs text-accent hover:underline"
                      onClick={() =>
                        run(() => api.groups.updateMember(group.id, member.user_id, { role: member.role === "admin" ? "member" : "admin" }))
                      }
                    >
                      {member.role === "admin" ? g.makeMember : g.makeAdmin}
                    </button>
                    <button type="button" className="text-xs text-danger hover:underline" onClick={() => run(() => api.groups.removeMember(group.id, member.user_id))}>
                      {g.remove}
                    </button>
                  </span>
                )}
              </li>
            ))}
          </ul>
          <label className="flex items-start gap-3 rounded-control border border-line p-3 text-sm">
            <input
              type="checkbox"
              className="mt-1 size-4 accent-[var(--accent)]"
              checked={group.my_share_activity}
              onChange={(event) => run(() => api.groups.updateMember(group.id, myId, { share_activity: event.target.checked }))}
            />
            <span>
              <span className="text-ink">{g.shareActivity}</span>
              <span className="block text-xs text-ink-muted">{g.shareActivityHint}</span>
            </span>
          </label>
          {manager && (
            <form onSubmit={invite} className="space-y-2">
              <Field label={g.invite}>
                {(props) => (
                  <div className="flex gap-2">
                    <Input {...props} type="email" required placeholder={g.email} value={email} onChange={(event) => setEmail(event.target.value)} />
                    <Button type="submit" pending={pending}>
                      <UserPlus aria-hidden className="size-4" />
                      {g.inviteButton}
                    </Button>
                  </div>
                )}
              </Field>
              {inviteLink && (
                <Alert tone="info">
                  <p>{g.inviteLink}</p>
                  <code className="mt-1 block text-xs break-all" dir="ltr">{inviteLink}</code>
                </Alert>
              )}
              {group.pending_invites.length > 0 && (
                <p className="text-xs text-ink-faint">
                  {g.pending}: {group.pending_invites.map((invite) => invite.email).join(", ")}
                </p>
              )}
            </form>
          )}
        </div>
        <div className="rounded-control border border-line">
          <h3 className="border-b border-line px-5 py-3 text-sm font-semibold text-ink">{g.sharedResults}</h3>
          <SharedFeed groupId={group.id} />
        </div>
      </div>
    </Panel>
  );
}

export function Groups() {
  const { t } = useI18n();
  const g = t.extra.groups;
  const notify = useToast();
  const { session } = useSession();
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<GroupKind>("family");
  const myId = session.status === "signed-in" ? session.user.id : "";

  const load = useCallback(() => {
    api.groups.list().then(setGroups).catch(() => setGroups([]));
  }, []);

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get("invite");
    if (!token) {
      load();
      return;
    }
    window.history.replaceState(null, "", "/dashboard/groups");
    api.groups
      .accept(token)
      .then((group) => notify("success", g.joined(group.name)))
      .catch((error) => notify("error", errorText(error)))
      .finally(load);
  }, [load, notify, g]);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    try {
      await api.groups.create(name.trim(), kind);
      setName("");
      load();
    } catch (error) {
      notify("error", errorText(error));
    }
  };

  return (
    <div className="space-y-6">
      <PageTitle title={g.title} description={g.description} />
      <Panel>
        <PanelHeader title={g.create} />
        <form onSubmit={create} className="flex flex-wrap items-end gap-3 p-5">
          <div className="min-w-48 flex-1">
            <Field label={g.name}>
              {(props) => <Input {...props} required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} />}
            </Field>
          </div>
          <Field label={g.kind}>
            {(props) => (
              <Select {...props} value={kind} onChange={(event) => setKind(event.target.value as GroupKind)}>
                <option value="family">{g.family}</option>
                <option value="organisation">{g.organisation}</option>
              </Select>
            )}
          </Field>
          <Button type="submit">
            <Plus aria-hidden className="size-4" />
            {g.createButton}
          </Button>
        </form>
      </Panel>
      {groups === null ? null : groups.length === 0 ? (
        <p className="text-ink-muted">{g.none}</p>
      ) : (
        groups.map((group) => <GroupCard key={group.id} group={group} myId={myId} onChange={() => load()} />)
      )}
      <p className="text-sm text-ink-faint">
        <Link href="/dashboard/history" className="underline">{t.dashboard.nav.history}</Link>
      </p>
    </div>
  );
}

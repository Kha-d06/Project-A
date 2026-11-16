"use client";

import { RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api/client";
import type { AdminOverview, AdminScan, AdminUser, AuditEntry } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatDateTime, formatRelative } from "@/lib/format";
import { SCAN_TYPE_LABEL, STATUS_LABEL } from "@/lib/risk";

function message(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function Health({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span aria-hidden className={cn("size-2 rounded-full", ok ? "bg-clear" : "bg-warning")} />
      <span className="sr-only">{ok ? "Healthy:" : "Needs attention:"}</span>
      {children}
    </span>
  );
}

function OverviewPanels({ overview, onSync }: { overview: AdminOverview; onSync: () => void }) {
  const scans = Object.entries(overview.scans_24h);
  const rejections = Object.entries(overview.rate_limit_rejections_24h).filter(([, count]) => count > 0);
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel>
        <PanelHeader title="Service health" />
        <dl className="divide-y divide-line text-sm">
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">Scan workers</dt>
            <dd><Health ok={overview.workers.reachable}>{overview.workers.detail}</Health></dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">Queued tasks</dt>
            <dd>{overview.workers.queued_tasks ?? "unknown"}</dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">Scans in the last 24 h</dt>
            <dd>{scans.length ? scans.map(([status, count]) => `${STATUS_LABEL[status as keyof typeof STATUS_LABEL] ?? status} ${count}`).join(" · ") : "none"}</dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">Stuck scans (over 15 min)</dt>
            <dd><Health ok={overview.stuck === 0}>{overview.stuck}</Health></dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">Accounts</dt>
            <dd>{overview.users_total} ({overview.users_new_7d} new this week)</dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">Reports awaiting review</dt>
            <dd>
              <a href="/dashboard/moderation" className="text-accent underline underline-offset-4">{overview.reports_pending}</a>
            </dd>
          </div>
        </dl>
      </Panel>
      <div className="space-y-6">
        <Panel>
          <PanelHeader
            title="Threat feeds"
            action={
              <Button size="sm" variant="secondary" onClick={onSync}>
                <RefreshCw aria-hidden className="size-4" />
                Sync now
              </Button>
            }
          />
          <ul className="divide-y divide-line text-sm">
            {overview.feeds.map((feed) => (
              <li key={feed.name} className="space-y-1 px-5 py-3">
                <Health ok={feed.fresh}>
                  <span className="font-medium text-ink">{feed.name}</span>
                </Health>
                <p className="text-ink-muted">
                  {feed.indicators.toLocaleString()} indicators ·{" "}
                  {feed.last_success_at ? `updated ${formatRelative(feed.last_success_at)}` : "never synchronised"}
                </p>
                {feed.last_error && <p className="text-warning">Last error: {feed.last_error}</p>}
              </li>
            ))}
          </ul>
        </Panel>
        <Panel>
          <PanelHeader title="Rate-limit rejections, last 24 h" description="Requests refused to protect the service. Spikes can indicate abuse." />
          {rejections.length === 0 ? (
            <p className="px-5 py-4 text-sm text-ink-muted">No requests were rejected.</p>
          ) : (
            <ul className="divide-y divide-line text-sm">
              {rejections.map(([name, count]) => (
                <li key={name} className="flex justify-between px-5 py-2.5">
                  <span className="font-mono text-xs">{name}</span>
                  <span>{count}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

function Users() {
  const notify = useToast();
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [users, setUsers] = useState<{ items: AdminUser[]; total: number } | null>(null);

  const load = useCallback(() => {
    api.admin.users(submitted || undefined).then(setUsers, (caught: unknown) => notify("error", message(caught, "Users could not be loaded.")));
  }, [submitted, notify]);

  useEffect(load, [load]);

  const update = async (user: AdminUser, body: { role?: AdminUser["role"]; disabled?: boolean }) => {
    try {
      await api.admin.updateUser(user.id, body);
      notify("success", `${user.email} updated.`);
      load();
    } catch (caught) {
      notify("error", message(caught, "The account could not be updated."));
    }
  };

  return (
    <Panel>
      <PanelHeader
        title="Accounts"
        description={users ? `${users.total} account(s)` : undefined}
        action={
          <form
            className="flex gap-2"
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              setSubmitted(query.trim());
            }}
          >
            <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search email or name" aria-label="Search accounts" className="h-8 w-56" />
            <Button type="submit" size="sm" variant="secondary">Search</Button>
          </form>
        }
      />
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <caption className="sr-only">Accounts</caption>
          <thead className="border-b border-line text-xs text-ink-faint">
            <tr>
              <th scope="col" className="px-5 py-2 text-start font-medium">Email</th>
              <th scope="col" className="px-3 py-2 text-start font-medium">Joined</th>
              <th scope="col" className="px-3 py-2 text-start font-medium">Scans</th>
              <th scope="col" className="px-3 py-2 text-start font-medium">Role</th>
              <th scope="col" className="px-5 py-2 text-start font-medium">Access</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {users?.items.map((user) => (
              <tr key={user.id}>
                <td className="px-5 py-2.5">{user.email}</td>
                <td className="px-3 py-2.5 whitespace-nowrap text-ink-muted">{formatDateTime(user.created_at)}</td>
                <td className="px-3 py-2.5">{user.scans}</td>
                <td className="px-3 py-2.5">
                  <Select
                    aria-label={`Role for ${user.email}`}
                    value={user.role}
                    onChange={(event) => update(user, { role: event.target.value as AdminUser["role"] })}
                    className="h-8"
                  >
                    <option value="user">User</option>
                    <option value="moderator">Moderator</option>
                    <option value="admin">Administrator</option>
                  </Select>
                </td>
                <td className="px-5 py-2.5">
                  <Button size="sm" variant={user.disabled ? "secondary" : "danger"} onClick={() => update(user, { disabled: !user.disabled })}>
                    {user.disabled ? "Enable" : "Disable"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function ScanJobs() {
  const [status, setStatus] = useState("failed");
  const [scans, setScans] = useState<AdminScan[] | null>(null);

  useEffect(() => {
    api.admin.scans(status || undefined).then(setScans, () => setScans([]));
  }, [status]);

  return (
    <Panel>
      <PanelHeader
        title="Scan jobs"
        description="Job metadata only. What people scanned is not shown here."
        action={
          <Select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by status" className="h-8">
            <option value="failed">Failed</option>
            <option value="queued">Queued</option>
            <option value="processing">Processing</option>
            <option value="">All</option>
          </Select>
        }
      />
      {scans?.length === 0 ? (
        <p className="px-5 py-4 text-sm text-ink-muted">No jobs match.</p>
      ) : (
        <ul className="divide-y divide-line text-sm">
          {scans?.map((scan) => (
            <li key={scan.id} className="flex flex-wrap gap-x-4 gap-y-1 px-5 py-2.5">
              <span className="w-28 text-ink">{SCAN_TYPE_LABEL[scan.scan_type]}</span>
              <span className="w-28 text-ink-muted">{STATUS_LABEL[scan.status]}</span>
              <span className="text-ink-muted">{formatDateTime(scan.created_at)}</span>
              {scan.duration_seconds !== null && <span className="text-ink-faint">{scan.duration_seconds.toFixed(1)} s</span>}
              {scan.error && <span className="basis-full text-warning">{scan.error}</span>}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function Audit() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  useEffect(() => {
    api.admin.audit().then((page) => setEntries(page.items), () => setEntries([]));
  }, []);
  return (
    <Panel>
      <PanelHeader title="Audit log" description="Sign-ins, security changes and administrative actions." />
      <ul className="divide-y divide-line text-sm">
        {entries?.map((entry, index) => (
          <li key={`${entry.created_at}-${index}`} className="flex flex-wrap gap-x-4 gap-y-0.5 px-5 py-2">
            <span className="font-mono text-xs text-ink">{entry.action}</span>
            <span className="text-ink-muted">{entry.user_email ?? "unknown account"}</span>
            {entry.detail && <span className="text-ink-muted">{entry.detail}</span>}
            <span className="ms-auto text-xs text-ink-faint">
              {entry.ip_address} · {formatRelative(entry.created_at)}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function AdminConsole() {
  const notify = useToast();
  const [overview, setOverview] = useState<AdminOverview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.admin.overview().then(setOverview, (caught: unknown) => setError(message(caught, "The admin overview could not be loaded.")));
  }, []);
  useEffect(load, [load]);

  const sync = async () => {
    try {
      const result = await api.admin.syncFeeds();
      notify("success", result.status === "queued" ? "Feed sync started." : "Feeds synchronised.");
      load();
    } catch (caught) {
      notify("error", message(caught, "The sync could not be started."));
    }
  };

  return (
    <>
      <PageTitle title="Administration" description="Service health, accounts, jobs and audit trail." />
      {error && <Alert tone="warning">{error}</Alert>}
      <div className="space-y-6">
        {overview && <OverviewPanels overview={overview} onSync={sync} />}
        <Users />
        <div className="grid gap-6 lg:grid-cols-2">
          <ScanJobs />
          <Audit />
        </div>
      </div>
    </>
  );
}

"use client";

import { RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";

import { AdminStats } from "@/components/admin/admin-stats";
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
import { useI18n } from "@/lib/i18n/client";

function message(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function Health({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  const { t } = useI18n();
  const s = t.extra.staff;
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span aria-hidden className={cn("size-2 rounded-full", ok ? "bg-clear" : "bg-warning")} />
      <span className="sr-only">{ok ? s.healthy : s.attention}</span>
      {children}
    </span>
  );
}

function OverviewPanels({ overview, onSync }: { overview: AdminOverview; onSync: () => void }) {
  const { t } = useI18n();
  const s = t.extra.staff;
  const scans = Object.entries(overview.scans_24h);
  const rejections = Object.entries(overview.rate_limit_rejections_24h).filter(([, count]) => count > 0);
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel>
        <PanelHeader title={s.serviceHealth} />
        <dl className="divide-y divide-line text-sm">
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">{s.scanWorkers}</dt>
            <dd><Health ok={overview.workers.reachable}>{overview.workers.detail}</Health></dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">{s.queuedTasks}</dt>
            <dd>{overview.workers.queued_tasks ?? s.unknown}</dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">{s.scans24h}</dt>
            <dd>{scans.length ? scans.map(([status, count]) => `${t.status[status as keyof typeof t.status] ?? status} ${count}`).join(" · ") : s.none}</dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">{s.stuck}</dt>
            <dd><Health ok={overview.stuck === 0}>{overview.stuck}</Health></dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">{s.accounts}</dt>
            <dd>{s.newThisWeek(overview.users_total, overview.users_new_7d)}</dd>
          </div>
          <div className="flex justify-between gap-4 px-5 py-3">
            <dt className="text-ink-muted">{s.pendingReports}</dt>
            <dd>
              <a href="/dashboard/moderation" className="text-accent underline underline-offset-4">{overview.reports_pending}</a>
            </dd>
          </div>
        </dl>
      </Panel>
      <div className="space-y-6">
        <Panel>
          <PanelHeader
            title={s.feeds}
            action={
              <Button size="sm" variant="secondary" onClick={onSync}>
                <RefreshCw aria-hidden className="size-4" />
                {s.syncNow}
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
                  {s.indicators(feed.indicators.toLocaleString())} ·{" "}
                  {feed.last_success_at ? s.updated(formatRelative(feed.last_success_at)) : s.neverSynced}
                </p>
                {feed.last_error && <p className="text-warning">{s.lastError(feed.last_error)}</p>}
              </li>
            ))}
          </ul>
        </Panel>
        <Panel>
          <PanelHeader title={s.rejections} description={s.rejectionsHint} />
          {rejections.length === 0 ? (
            <p className="px-5 py-4 text-sm text-ink-muted">{s.noRejections}</p>
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
  const { t } = useI18n();
  const s = t.extra.staff;
  const notify = useToast();
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [users, setUsers] = useState<{ items: AdminUser[]; total: number } | null>(null);

  const load = useCallback(() => {
    api.admin.users(submitted || undefined).then(setUsers, (caught: unknown) => notify("error", message(caught, s.usersFailed)));
  }, [submitted, notify, s]);

  useEffect(load, [load]);

  const update = async (user: AdminUser, body: { role?: AdminUser["role"]; disabled?: boolean }) => {
    try {
      await api.admin.updateUser(user.id, body);
      notify("success", s.userUpdated(user.email));
      load();
    } catch (caught) {
      notify("error", message(caught, s.userFailed));
    }
  };

  return (
    <Panel>
      <PanelHeader
        title={s.accounts}
        description={users ? s.accountsCount(users.total) : undefined}
        action={
          <form
            className="flex gap-2"
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              setSubmitted(query.trim());
            }}
          >
            <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={s.searchPlaceholder} aria-label={s.searchPlaceholder} className="h-8 w-56" />
            <Button type="submit" size="sm" variant="secondary">{s.search}</Button>
          </form>
        }
      />
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <caption className="sr-only">{s.accounts}</caption>
          <thead className="border-b border-line text-xs text-ink-faint">
            <tr>
              <th scope="col" className="px-5 py-2 text-start font-medium">{s.email}</th>
              <th scope="col" className="px-3 py-2 text-start font-medium">{s.joined}</th>
              <th scope="col" className="px-3 py-2 text-start font-medium">{s.scans}</th>
              <th scope="col" className="px-3 py-2 text-start font-medium">{s.role}</th>
              <th scope="col" className="px-5 py-2 text-start font-medium">{s.access}</th>
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
                    aria-label={s.roleFor(user.email)}
                    value={user.role}
                    onChange={(event) => update(user, { role: event.target.value as AdminUser["role"] })}
                    className="h-8"
                  >
                    <option value="user">{s.roles.user}</option>
                    <option value="moderator">{s.roles.moderator}</option>
                    <option value="admin">{s.roles.admin}</option>
                  </Select>
                </td>
                <td className="px-5 py-2.5">
                  <Button size="sm" variant={user.disabled ? "secondary" : "danger"} onClick={() => update(user, { disabled: !user.disabled })}>
                    {user.disabled ? s.enable : s.disable}
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
  const { t } = useI18n();
  const s = t.extra.staff;
  const [status, setStatus] = useState("failed");
  const [scans, setScans] = useState<AdminScan[] | null>(null);

  useEffect(() => {
    api.admin.scans(status || undefined).then(setScans, () => setScans([]));
  }, [status]);

  return (
    <Panel>
      <PanelHeader
        title={s.jobs}
        description={s.jobsHint}
        action={
          <Select value={status} onChange={(event) => setStatus(event.target.value)} aria-label={s.filterStatus} className="h-8">
            <option value="failed">{s.jobStatus.failed}</option>
            <option value="queued">{s.jobStatus.queued}</option>
            <option value="processing">{s.jobStatus.processing}</option>
            <option value="">{s.jobStatus.all}</option>
          </Select>
        }
      />
      {scans?.length === 0 ? (
        <p className="px-5 py-4 text-sm text-ink-muted">{s.noJobs}</p>
      ) : (
        <ul className="divide-y divide-line text-sm">
          {scans?.map((scan) => (
            <li key={scan.id} className="flex flex-wrap gap-x-4 gap-y-1 px-5 py-2.5">
              <span className="w-28 text-ink">{t.scanTypes[scan.scan_type]}</span>
              <span className="w-28 text-ink-muted">{t.status[scan.status]}</span>
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
  const { t } = useI18n();
  const s = t.extra.staff;
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  useEffect(() => {
    api.admin.audit().then((page) => setEntries(page.items), () => setEntries([]));
  }, []);
  return (
    <Panel>
      <PanelHeader title={s.audit} description={s.auditHint} />
      <ul className="divide-y divide-line text-sm">
        {entries?.map((entry, index) => (
          <li key={`${entry.created_at}-${index}`} className="flex flex-wrap gap-x-4 gap-y-0.5 px-5 py-2">
            <span className="font-mono text-xs text-ink">{entry.action}</span>
            <span className="text-ink-muted">{entry.user_email ?? s.unknownAccount}</span>
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
  const { t } = useI18n();
  const s = t.extra.staff;
  const notify = useToast();
  const [overview, setOverview] = useState<AdminOverview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.admin.overview().then(setOverview, (caught: unknown) => setError(message(caught, s.overviewFailed)));
  }, [s]);
  useEffect(load, [load]);

  const sync = async () => {
    try {
      const result = await api.admin.syncFeeds();
      notify("success", result.status === "queued" ? s.syncStarted : s.synced);
      load();
    } catch (caught) {
      notify("error", message(caught, s.syncFailed));
    }
  };

  return (
    <>
      <PageTitle title={s.administration} description={s.administrationHint} />
      {error && <Alert tone="warning">{error}</Alert>}
      <div className="space-y-6">
        <AdminStats />
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

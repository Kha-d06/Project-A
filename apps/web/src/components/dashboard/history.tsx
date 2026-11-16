"use client";

import { Trash2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { RiskBadge } from "@/components/scan/risk-badge";
import { Alert } from "@/components/ui/alert";
import { Button, ButtonLink } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Panel } from "@/components/ui/panel";
import { Select } from "@/components/ui/field";
import { useToast } from "@/components/ui/toast";
import { ApiError, api, type HistoryFilters } from "@/lib/api/client";
import type { ScanPage } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

const PAGE_SIZE = 20;

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: [string, string][];
}) {
  const { t } = useI18n();
  return (
    <label className="space-y-1 text-sm">
      <span className="block text-ink-muted">{label}</span>
      <Select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">{t.dashboard.history.all}</option>
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </Select>
    </label>
  );
}

function DateFilter({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="space-y-1 text-sm">
      <span className="block text-ink-muted">{label}</span>
      <input
        type="date"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-10 w-full rounded-control border border-line-strong bg-surface px-3 text-ink"
      />
    </label>
  );
}

/** Date inputs give local calendar days; the API filters on instants. */
function dayBoundary(day: string, end: boolean): string | undefined {
  if (!day) return undefined;
  const date = new Date(`${day}T00:00:00`);
  if (end) date.setDate(date.getDate() + 1);
  return date.toISOString();
}

export function History() {
  const notify = useToast();
  const { t } = useI18n();
  const h = t.dashboard.history;
  const [filters, setFilters] = useState({ type: "", risk: "", status: "", since: "", until: "" });
  const [page, setPage] = useState(1);
  const [result, setResult] = useState<ScanPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [busy, setBusy] = useState(false);

  // Bumped after a deletion to fetch the current page again.
  const [reloadKey, setReloadKey] = useState(0);
  const reload = () => setReloadKey((key) => key + 1);

  useEffect(() => {
    let cancelled = false;
    api.scans
      .history({
        type: filters.type as HistoryFilters["type"],
        risk: filters.risk as HistoryFilters["risk"],
        status: filters.status as HistoryFilters["status"],
        since: dayBoundary(filters.since, false),
        until: dayBoundary(filters.until, true),
        page,
        pageSize: PAGE_SIZE,
      })
      .then(
        (loaded) => {
          if (cancelled) return;
          setResult(loaded);
          setError(null);
        },
        (caught: unknown) => {
          if (cancelled) return;
          setError(caught instanceof ApiError ? caught.message : h.loadFailed);
        },
      );
    return () => {
      cancelled = true;
    };
  }, [filters, page, reloadKey, h.loadFailed]);

  const setFilter = (key: keyof typeof filters) => (value: string) => {
    setPage(1);
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const removeOne = async (id: string) => {
    try {
      await api.scans.remove(id);
      notify("success", h.deleted);
      reload();
    } catch (caught) {
      notify("error", caught instanceof ApiError ? caught.message : h.deleteFailed);
    }
  };

  const clearAll = async () => {
    setBusy(true);
    try {
      await api.scans.clearHistory();
      notify("success", h.cleared);
      setConfirmClear(false);
      setPage(1);
      reload();
    } catch (caught) {
      notify("error", caught instanceof ApiError ? caught.message : h.clearFailed);
    } finally {
      setBusy(false);
    }
  };

  const filtered = Object.values(filters).some(Boolean);
  const pages = result ? Math.max(1, Math.ceil(result.total / PAGE_SIZE)) : 1;

  return (
    <>
      <PageTitle
        title={h.title}
        description={h.description}
        action={
          result && result.total > 0 && !filtered ? (
            <Button variant="danger" size="sm" onClick={() => setConfirmClear(true)}>
              <Trash2 aria-hidden className="size-4" />
              {h.deleteAll}
            </Button>
          ) : undefined
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-5">
        <FilterSelect label={h.type} value={filters.type} onChange={setFilter("type")} options={Object.entries(t.scanTypes)} />
        <FilterSelect
          label={h.result}
          value={filters.risk}
          onChange={setFilter("risk")}
          options={Object.entries(t.risk).map(([key, value]) => [key, value.short])}
        />
        <FilterSelect
          label={h.status}
          value={filters.status}
          onChange={setFilter("status")}
          options={Object.entries(t.status).filter(([key]) => key !== "scanFailed")}
        />
        <DateFilter label={h.from} value={filters.since} onChange={setFilter("since")} />
        <DateFilter label={h.to} value={filters.until} onChange={setFilter("until")} />
      </div>

      {error && <Alert tone="warning">{error}</Alert>}

      {result && result.items.length === 0 && (
        <Panel className="px-6 py-12 text-center">
          <p className="font-medium text-ink">{filtered ? h.noMatchTitle : h.emptyTitle}</p>
          <p className="mt-1 text-sm text-ink-muted">{filtered ? h.noMatchBody : h.emptyBody}</p>
          {!filtered && (
            <ButtonLink href="/dashboard/scan" className="mt-5">
              {h.start}
            </ButtonLink>
          )}
        </Panel>
      )}

      {result && result.items.length > 0 && (
        <Panel className="overflow-hidden">
          <table className="w-full text-sm">
            <caption className="sr-only">{h.caption}</caption>
            <thead className="hidden border-b border-line bg-surface-sunken/60 text-start text-xs text-ink-faint md:table-header-group">
              <tr>
                <th scope="col" className="px-5 py-2.5 text-start font-medium">{h.item}</th>
                <th scope="col" className="px-3 py-2.5 text-start font-medium">{h.type}</th>
                <th scope="col" className="px-3 py-2.5 text-start font-medium">{h.submitted}</th>
                <th scope="col" className="px-3 py-2.5 text-start font-medium">{h.result}</th>
                <th scope="col" className="px-5 py-2.5">
                  <span className="sr-only">{h.actions}</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {result.items.map((scan) => (
                <tr key={scan.id} className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1.5 px-5 py-3 md:table-row md:p-0">
                  <td className="col-span-2 min-w-0 md:max-w-0 md:px-5 md:py-3 md:w-1/2">
                    <Link href={`/dashboard/scans/${scan.id}`} className="block truncate font-mono text-[0.8rem] text-ink hover:text-accent" dir="auto">
                      {scan.target}
                    </Link>
                  </td>
                  <td className="text-ink-muted md:px-3 md:py-3">{t.scanTypes[scan.scan_type]}</td>
                  <td className="text-end text-ink-muted md:px-3 md:py-3 md:text-start md:whitespace-nowrap">{formatDateTime(scan.created_at)}</td>
                  <td className="md:px-3 md:py-3"><RiskBadge risk={scan.risk} status={scan.status} /></td>
                  <td className="text-end md:px-5 md:py-3">
                    <button
                      type="button"
                      onClick={() => removeOne(scan.id)}
                      className="rounded-control p-1.5 text-ink-faint hover:bg-danger-soft hover:text-danger"
                      aria-label={h.deleteOne(scan.target)}
                    >
                      <Trash2 aria-hidden className="size-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {pages > 1 && (
            <nav aria-label={h.pagination} className="flex items-center justify-between border-t border-line px-5 py-3 text-sm text-ink-muted">
              <span>{h.page(page, pages, result.total)}</span>
              <div className="flex gap-2">
                <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>{h.previous}</Button>
                <Button variant="secondary" size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>{h.next}</Button>
              </div>
            </nav>
          )}
        </Panel>
      )}

      <Dialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title={h.confirmTitle}
        description={h.confirmBody}
      >
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirmClear(false)}>
            {t.common.cancel}
          </Button>
          <Button variant="danger" pending={busy} onClick={clearAll}>
            {h.confirm}
          </Button>
        </div>
      </Dialog>
    </>
  );
}

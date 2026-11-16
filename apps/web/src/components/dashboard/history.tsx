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
import { RISK, SCAN_TYPE_LABEL, STATUS_LABEL } from "@/lib/risk";

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
  return (
    <label className="space-y-1 text-sm">
      <span className="block text-ink-muted">{label}</span>
      <Select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">All</option>
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
          setError(caught instanceof ApiError ? caught.message : "Your history could not be loaded.");
        },
      );
    return () => {
      cancelled = true;
    };
  }, [filters, page, reloadKey]);

  const setFilter = (key: keyof typeof filters) => (value: string) => {
    setPage(1);
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const removeOne = async (id: string) => {
    try {
      await api.scans.remove(id);
      notify("success", "Scan deleted.");
      reload();
    } catch (caught) {
      notify("error", caught instanceof ApiError ? caught.message : "The scan could not be deleted.");
    }
  };

  const clearAll = async () => {
    setBusy(true);
    try {
      await api.scans.clearHistory();
      notify("success", "Your scan history was deleted.");
      setConfirmClear(false);
      setPage(1);
      reload();
    } catch (caught) {
      notify("error", caught instanceof ApiError ? caught.message : "Your history could not be deleted.");
    } finally {
      setBusy(false);
    }
  };

  const filtered = Object.values(filters).some(Boolean);
  const pages = result ? Math.max(1, Math.ceil(result.total / PAGE_SIZE)) : 1;

  return (
    <>
      <PageTitle
        title="Scan history"
        description="Every scan saved to your account, with its full report."
        action={
          result && result.total > 0 && !filtered ? (
            <Button variant="danger" size="sm" onClick={() => setConfirmClear(true)}>
              <Trash2 aria-hidden className="size-4" />
              Delete all
            </Button>
          ) : undefined
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-5">
        <FilterSelect label="Type" value={filters.type} onChange={setFilter("type")} options={Object.entries(SCAN_TYPE_LABEL)} />
        <FilterSelect
          label="Result"
          value={filters.risk}
          onChange={setFilter("risk")}
          options={Object.entries(RISK).map(([key, value]) => [key, value.short])}
        />
        <FilterSelect label="Status" value={filters.status} onChange={setFilter("status")} options={Object.entries(STATUS_LABEL)} />
        <DateFilter label="From" value={filters.since} onChange={setFilter("since")} />
        <DateFilter label="To" value={filters.until} onChange={setFilter("until")} />
      </div>

      {error && <Alert tone="warning">{error}</Alert>}

      {result && result.items.length === 0 && (
        <Panel className="px-6 py-12 text-center">
          <p className="font-medium text-ink">{filtered ? "No scans match these filters" : "No saved scans yet"}</p>
          <p className="mt-1 text-sm text-ink-muted">
            {filtered ? "Try widening the date range or clearing a filter." : "Scans you run while signed in will appear here."}
          </p>
          {!filtered && (
            <ButtonLink href="/dashboard/scan" className="mt-5">
              Start a scan
            </ButtonLink>
          )}
        </Panel>
      )}

      {result && result.items.length > 0 && (
        <Panel className="overflow-hidden">
          <table className="w-full text-sm">
            <caption className="sr-only">Saved scans, newest first</caption>
            <thead className="hidden border-b border-line bg-surface-sunken/60 text-start text-xs text-ink-faint md:table-header-group">
              <tr>
                <th scope="col" className="px-5 py-2.5 text-start font-medium">Item</th>
                <th scope="col" className="px-3 py-2.5 text-start font-medium">Type</th>
                <th scope="col" className="px-3 py-2.5 text-start font-medium">Submitted</th>
                <th scope="col" className="px-3 py-2.5 text-start font-medium">Result</th>
                <th scope="col" className="px-5 py-2.5"><span className="sr-only">Actions</span></th>
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
                  <td className="text-ink-muted md:px-3 md:py-3">{SCAN_TYPE_LABEL[scan.scan_type]}</td>
                  <td className="text-end text-ink-muted md:px-3 md:py-3 md:text-start md:whitespace-nowrap">{formatDateTime(scan.created_at)}</td>
                  <td className="md:px-3 md:py-3"><RiskBadge risk={scan.risk} status={scan.status} /></td>
                  <td className="text-end md:px-5 md:py-3">
                    <button
                      type="button"
                      onClick={() => removeOne(scan.id)}
                      className="rounded-control p-1.5 text-ink-faint hover:bg-danger-soft hover:text-danger"
                      aria-label={`Delete scan of ${scan.target}`}
                    >
                      <Trash2 aria-hidden className="size-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {pages > 1 && (
            <nav aria-label="Pagination" className="flex items-center justify-between border-t border-line px-5 py-3 text-sm text-ink-muted">
              <span>
                Page {page} of {pages} · {result.total} scans
              </span>
              <div className="flex gap-2">
                <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button>
                <Button variant="secondary" size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</Button>
              </div>
            </nav>
          )}
        </Panel>
      )}

      <Dialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title="Delete your whole scan history?"
        description="All saved scans and their reports will be permanently deleted. This cannot be undone."
      >
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirmClear(false)}>Cancel</Button>
          <Button variant="danger" pending={busy} onClick={clearAll}>Delete history</Button>
        </div>
      </Dialog>
    </>
  );
}

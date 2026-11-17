"use client";

import { Search } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { RiskBadge } from "@/components/scan/risk-badge";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { LookupResult, PublicReport } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

/** Works out what kind of indicator the user typed. */
export function lookupKind(value: string): "domain" | "ip" | "hash" | "phone" | null {
  const text = value.trim();
  if (/^[a-fA-F0-9]{32,64}$/.test(text)) return "hash";
  if (/^(\+|00)?[\d\s().-]{7,20}$/.test(text) && text.replace(/\D/g, "").length >= 7 && !/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) return "phone";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text) || (text.includes(":") && /^[0-9a-fA-F:]+$/.test(text))) return "ip";
  const host = text.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0] ?? "";
  return host.includes(".") ? "domain" : null;
}

const VERDICT_RISK = {
  listed: "known_malicious",
  community_verified: "suspicious",
  not_listed: "no_known_threat",
  unavailable: "inconclusive",
} as const;

function Result({ result }: { result: LookupResult }) {
  const { t } = useI18n();
  return (
    <Panel className="animate-fade-up">
      <PanelHeader
        title={<span className="font-mono text-sm break-all">{result.query}</span>}
        description={t.intel.verdicts[result.verdict]}
        action={<RiskBadge risk={VERDICT_RISK[result.verdict]} status="completed" />}
      />
      {result.indicators.length > 0 && (
        <ul className="divide-y divide-line">
          {result.indicators.map((indicator) => (
            <li key={`${indicator.source}-${indicator.value}`} className="space-y-1 px-5 py-3 text-sm">
              <p className="font-mono text-[0.8rem] break-all text-ink">{indicator.value}</p>
              <p className="text-ink-muted">
                {indicator.source}
                {indicator.threat && ` · ${indicator.threat.replaceAll("_", " ")}`}
                {indicator.first_seen && ` · ${t.intel.firstReported(formatDateTime(indicator.first_seen))}`}
              </p>
            </li>
          ))}
        </ul>
      )}
      <div className="space-y-2 border-t border-line px-5 py-4 text-sm text-ink-muted">
        {result.kind === "phone" && result.country && <p className="text-ink">{t.extra.phone.country(result.country)}</p>}
        {result.kind === "phone" && !!result.reports_awaiting_review && (
          <p className="text-warning">{t.extra.phone.pending(result.reports_awaiting_review)}</p>
        )}
        {result.notes.map((note) => (
          <p key={note} dir="auto">
            {note}
          </p>
        ))}
        <p className="text-xs text-ink-faint">
          {t.intel.sourcesChecked}{" "}
          {result.sources.length === 0
            ? t.intel.noSources
            : result.sources
                .map(
                  (s) =>
                    `${s.name} (${s.last_updated ? t.intel.updated(formatRelative(s.last_updated)) : t.intel.neverUpdated}${s.fresh ? "" : `, ${t.intel.outOfDate}`})`,
                )
                .join("; ")}
        </p>
      </div>
    </Panel>
  );
}

export function IntelLookup() {
  const { t } = useI18n();
  const [value, setValue] = useState("");
  const [result, setResult] = useState<LookupResult | null>(null);
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);
  const [verified, setVerified] = useState<PublicReport[] | null>(null);

  useEffect(() => {
    api.reports.publicList().then(setVerified, () => setVerified([]));
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const kind = lookupKind(value);
    if (!kind) {
      setError(t.intel.invalid);
      return;
    }
    setError(undefined);
    setPending(true);
    try {
      const query = kind === "domain" ? (value.trim().replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0] ?? "") : value.trim();
      setResult(await api.intelligence.lookup(kind, query));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof ApiError ? caught.message : t.intel.failed);
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-8">
      <form onSubmit={submit} noValidate className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="flex-1">
          <Field label={t.intel.field} error={error}>
            {(props) => (
              <Input
                {...props}
                value={value}
                onChange={(event) => setValue(event.target.value)}
                spellCheck={false}
                autoComplete="off"
                placeholder="example.com"
                className="font-mono text-[0.9rem]"
              />
            )}
          </Field>
        </div>
        <Button type="submit" size="lg" pending={pending} className={error ? "sm:mb-7" : undefined}>
          <Search aria-hidden className="size-4" />
          {t.intel.lookup}
        </Button>
      </form>

      {result && <Result result={result} />}

      <Panel>
        <PanelHeader
          title={t.intel.verifiedTitle}
          description={t.intel.verifiedDescription}
        />
        {verified === null ? (
          <div className="h-24 animate-pulse" aria-busy />
        ) : verified.length === 0 ? (
          <p className="px-5 py-5 text-sm text-ink-muted">{t.intel.noneVerified}</p>
        ) : (
          <ul className="divide-y divide-line">
            {verified.map((entry) => (
              <li key={`${entry.category}-${entry.subject}`} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                <span className="min-w-0 flex-1 truncate font-mono text-[0.8rem] text-ink" dir="ltr">
                  {entry.subject}
                </span>
                <span className="text-ink-muted">{t.community.categories[entry.category].label}</span>
                <span className="text-xs text-ink-faint">
                  {t.intel.reports(entry.reports)} · {t.intel.verified(formatRelative(entry.verified_at))}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

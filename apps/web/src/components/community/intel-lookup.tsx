"use client";

import { Search } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { RiskBadge } from "@/components/scan/risk-badge";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { LookupResult, PublicReport } from "@/lib/api/types";
import { CATEGORY } from "@/lib/community";
import { formatDateTime, formatRelative } from "@/lib/format";

/** Works out what kind of indicator the user typed. */
export function lookupKind(value: string): "domain" | "ip" | "hash" | null {
  const text = value.trim();
  if (/^[a-fA-F0-9]{32,64}$/.test(text)) return "hash";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text) || (text.includes(":") && /^[0-9a-fA-F:]+$/.test(text))) return "ip";
  const host = text.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0] ?? "";
  return host.includes(".") ? "domain" : null;
}

const VERDICT = {
  listed: { risk: "known_malicious", text: "Listed in threat intelligence" },
  community_verified: { risk: "suspicious", text: "Reported by users and verified by a moderator" },
  not_listed: { risk: "no_known_threat", text: "Not listed in the sources below" },
  unavailable: { risk: "inconclusive", text: "Cannot say: the threat feed is not up to date" },
} as const;

function Result({ result }: { result: LookupResult }) {
  const verdict = VERDICT[result.verdict];
  return (
    <Panel className="animate-fade-up">
      <PanelHeader
        title={<span className="font-mono text-sm break-all">{result.query}</span>}
        description={verdict.text}
        action={<RiskBadge risk={verdict.risk} status="completed" />}
      />
      {result.indicators.length > 0 && (
        <ul className="divide-y divide-line">
          {result.indicators.map((indicator) => (
            <li key={`${indicator.source}-${indicator.value}`} className="space-y-1 px-5 py-3 text-sm">
              <p className="font-mono text-[0.8rem] break-all text-ink">{indicator.value}</p>
              <p className="text-ink-muted">
                {indicator.source}
                {indicator.threat && ` · ${indicator.threat.replaceAll("_", " ")}`}
                {indicator.first_seen && ` · first reported ${formatDateTime(indicator.first_seen)}`}
              </p>
            </li>
          ))}
        </ul>
      )}
      <div className="space-y-2 border-t border-line px-5 py-4 text-sm text-ink-muted">
        {result.notes.map((note) => (
          <p key={note}>{note}</p>
        ))}
        <p className="text-xs text-ink-faint">
          Sources checked:{" "}
          {result.sources.length === 0
            ? "none available on this server"
            : result.sources
                .map((s) => `${s.name} (${s.last_updated ? `updated ${formatRelative(s.last_updated)}` : "never updated"}${s.fresh ? "" : ", out of date"})`)
                .join("; ")}
        </p>
      </div>
    </Panel>
  );
}

export function IntelLookup() {
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
      setError("Enter a domain (example.com), an IP address, or a SHA-256 file fingerprint.");
      return;
    }
    setError(undefined);
    setPending(true);
    try {
      const query = kind === "domain" ? (value.trim().replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0] ?? "") : value.trim();
      setResult(await api.intelligence.lookup(kind, query));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof ApiError ? caught.message : "The lookup failed.");
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-8">
      <form onSubmit={submit} noValidate className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="flex-1">
          <Field label="Domain, IP address or SHA-256 fingerprint" error={error}>
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
          Look up
        </Button>
      </form>

      {result && <Result result={result} />}

      <Panel>
        <PanelHeader
          title="Recently verified community reports"
          description="Reports from SENTINEL users that a moderator confirmed. Phone numbers are partly hidden because scammers often spoof real people’s numbers."
        />
        {verified === null ? (
          <div className="h-24 animate-pulse" aria-busy />
        ) : verified.length === 0 ? (
          <p className="px-5 py-5 text-sm text-ink-muted">No reports have been verified yet.</p>
        ) : (
          <ul className="divide-y divide-line">
            {verified.map((entry) => (
              <li key={`${entry.category}-${entry.subject}`} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                <span className="min-w-0 flex-1 truncate font-mono text-[0.8rem] text-ink" dir="ltr">
                  {entry.subject}
                </span>
                <span className="text-ink-muted">{CATEGORY[entry.category].label}</span>
                <span className="text-xs text-ink-faint">
                  {entry.reports} report{entry.reports === 1 ? "" : "s"} · verified {formatRelative(entry.verified_at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

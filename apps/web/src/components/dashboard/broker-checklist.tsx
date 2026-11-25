"use client";

import { ExternalLink } from "lucide-react";
import { useMemo, useState, useSyncExternalStore } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { CATALOG, STATES, letterFor, loadProgress, mark, rows, safeOptOutUrl, saveProgress, type BrokerRow, type BrokerState, type Progress } from "@/lib/brokers";
import { formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

// Progress lives in this browser only: a tiny store over localStorage, read
// after hydration so the server render and the first client render match.
const EMPTY: Progress = {};
let current: Progress | null = null;
let persisted = true;
const listeners = new Set<() => void>();
const store = {
  subscribe(listener: () => void) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  snapshot(): Progress {
    current ??= loadProgress();
    return current;
  },
  server: (): Progress => EMPTY,
  set(next: Progress) {
    current = next;
    persisted = saveProgress(next);
    for (const l of listeners) l();
  },
};

/** For tests: forget what the store has read. */
export function resetBrokerStore() {
  current = null;
  persisted = true;
}

export function BrokerChecklist({ now = () => Date.now() }: { now?: () => number }) {
  const notify = useToast();
  const { t } = useI18n();
  const p = t.extra.privacy;
  const progress = useSyncExternalStore(store.subscribe, store.snapshot, store.server);
  const view = useMemo(() => rows(progress, now()), [progress, now]);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [letterFor_, setLetterFor] = useState<string | null>(null);

  const set = (id: string, state: BrokerState) => store.set(mark(progress, id, state, now()));

  return (
    <Panel>
      <PanelHeader title={p.brokers} description={p.brokersExplain} />
      <div className="space-y-3 px-5 py-4 text-sm">
        <p className="text-ink-muted">
          {p.progress(view.done, view.rows.length)} · {p.catalog(CATALOG.version)}
        </p>
        <p className="text-ink-faint">{CATALOG.note}</p>
        {view.recheckDue > 0 && <Alert tone="warning">{p.recheckDue(view.recheckDue)}</Alert>}
        {!persisted && <Alert tone="info">{p.notSaved}</Alert>}
      </div>
      <ul className="divide-y divide-line">
        {view.rows.map((b) => (
          <BrokerItem key={b.id} broker={b} onMark={set} letterOpen={letterFor_ === b.id} onLetter={() => setLetterFor(letterFor_ === b.id ? null : b.id)}>
            {letterFor_ === b.id && <Letter broker={b} name={name} email={email} onName={setName} onEmail={setEmail} onCopied={() => notify("success", p.letterCopied)} onFailed={() => notify("error", p.failed)} />}
          </BrokerItem>
        ))}
      </ul>
    </Panel>
  );
}

function BrokerItem({ broker: b, onMark, letterOpen, onLetter, children }: { broker: BrokerRow; onMark: (id: string, s: BrokerState) => void; letterOpen: boolean; onLetter: () => void; children: React.ReactNode }) {
  const { t } = useI18n();
  const p = t.extra.privacy;
  const url = safeOptOutUrl(b);
  return (
    <li className="space-y-2 px-5 py-4 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium text-ink">{b.name}</p>
          <p className="text-ink-faint">
            <span dir="ltr">{b.site}</span> · {p.regions}: {b.regions.join(", ")} · {p.verification[b.verification] ?? b.verification} · {p.removal(b.removalDays)}
          </p>
          {b.at && (
            <p className={b.recheckDue ? "text-warning" : "text-ink-faint"}>
              {b.expectedBy ? p.expectedBy(formatShortDate(b.expectedBy)) : p.markedAt(formatShortDate(b.at))}
              {b.recheckDue ? ` · ${p.recheck}` : ""}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {url && (
            <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent underline-offset-2 hover:underline">
              {p.openPage} <ExternalLink className="size-3.5" aria-hidden />
            </a>
          )}
          <Select aria-label={`${b.name}: ${p.states[b.state]}`} value={b.state} onChange={(e) => onMark(b.id, e.target.value as BrokerState)} className="w-36">
            {STATES.map((s) => (
              <option key={s} value={s}>
                {p.states[s]}
              </option>
            ))}
          </Select>
          {b.recheckDue && (
            <Button size="sm" variant="secondary" onClick={() => onMark(b.id, b.state)}>
              {p.recheck}
            </Button>
          )}
          <Button size="sm" variant="secondary" aria-expanded={letterOpen} onClick={onLetter}>
            {p.letter}
          </Button>
        </div>
      </div>
      <ol className="list-decimal space-y-0.5 ps-5 text-ink-muted" dir="auto">
        {b.steps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      {children}
    </li>
  );
}

function Letter({ broker, name, email, onName, onEmail, onCopied, onFailed }: { broker: BrokerRow; name: string; email: string; onName: (v: string) => void; onEmail: (v: string) => void; onCopied: () => void; onFailed: () => void }) {
  const { t } = useI18n();
  const p = t.extra.privacy;
  const letter = letterFor(broker, name, email);
  const copy = async () => {
    if (!letter) return;
    try {
      await navigator.clipboard.writeText(`${letter.subject}\n\n${letter.body}`);
      onCopied();
    } catch {
      onFailed();
    }
  };
  return (
    <div className="space-y-3 rounded-lg border border-line p-4">
      <p className="text-ink-muted">{p.letterExplain}</p>
      <div className="flex flex-wrap gap-3">
        <Field label={p.yourName}>{(props) => <Input {...props} value={name} maxLength={120} autoComplete="name" onChange={(e) => onName(e.target.value)} className="w-56" />}</Field>
        <Field label={p.yourEmail}>{(props) => <Input {...props} type="email" value={email} maxLength={254} autoComplete="email" dir="ltr" onChange={(e) => onEmail(e.target.value)} className="w-64" />}</Field>
      </div>
      {letter ? (
        <>
          <Field label={letter.subject}>{(props) => <Textarea {...props} readOnly rows={10} value={letter.body} dir="ltr" />}</Field>
          <Button size="sm" onClick={() => void copy()}>
            {p.copyLetter}
          </Button>
        </>
      ) : (
        <p className="text-ink-faint">{p.letterNeeds}</p>
      )}
    </div>
  );
}

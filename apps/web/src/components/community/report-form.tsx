"use client";

import { CheckCircle2 } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { ApiError, api } from "@/lib/api/client";
import type { ReportCategory, ReportCreated } from "@/lib/api/types";
import { useI18n } from "@/lib/i18n/client";
import { useSession } from "@/lib/session";

export function ReportForm() {
  const { session } = useSession();
  const { t } = useI18n();
  const c = t.community;
  const [category, setCategory] = useState<ReportCategory>("website");
  const [subject, setSubject] = useState("");
  const [description, setDescription] = useState("");
  const [evidence, setEvidence] = useState("");
  const [anonymous, setAnonymous] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [pending, setPending] = useState(false);
  const [created, setCreated] = useState<ReportCreated | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const found: Record<string, string> = {};
    if (subject.trim().length < 3) found.subject = c.subjectMissing;
    if (description.trim().length < 10) found.description = c.descriptionMissing;
    setErrors(found);
    if (Object.keys(found).length) return;
    setPending(true);
    try {
      setCreated(
        await api.reports.create({ category, subject, description, evidence: evidence || undefined, anonymous }),
      );
    } catch (caught) {
      if (caught instanceof ApiError) {
        const fields = caught.fieldErrors();
        setErrors(Object.keys(fields).length ? fields : { form: caught.message });
      } else {
        setErrors({ form: c.failed });
      }
    } finally {
      setPending(false);
    }
  };

  if (created) {
    const trackHref = created.tracking_token
      ? `/reports/${created.report.id}?token=${encodeURIComponent(created.tracking_token)}`
      : "/dashboard/reports";
    return (
      <div className="animate-fade-up space-y-4 rounded-panel border border-line bg-surface p-6" role="status">
        <p className="flex items-center gap-2 font-display text-lg font-semibold text-ink">
          <CheckCircle2 aria-hidden className="size-5 text-accent" />
          {c.thanks}
        </p>
        <p className="text-sm text-ink-muted">
          {c.afterSend}
          {created.similar_reports > 0 && c.others(created.similar_reports)}
        </p>
        {created.tracking_token ? (
          <Alert title={c.keepLink}>
            <span className="break-all">
              {c.keepLinkBody}{" "}
              <Link className="text-accent underline" href={trackHref}>
                {c.viewStatus}
              </Link>
            </span>
          </Alert>
        ) : (
          <Link className="text-sm font-medium text-accent underline underline-offset-4" href={trackHref}>
            {c.seeReports}
          </Link>
        )}
      </div>
    );
  }

  const info = c.categories[category];
  return (
    <form onSubmit={submit} noValidate className="space-y-5">
      {errors.form && <Alert tone="danger">{errors.form}</Alert>}
      <Field label={c.what}>
        {(props) => (
          <Select {...props} value={category} onChange={(event) => setCategory(event.target.value as ReportCategory)} className="w-full">
            {Object.entries(c.categories).map(([value, item]) => (
              <option key={value} value={value}>
                {item.label}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label={info.subject} error={errors.subject}>
        {(props) => (
          <Input {...props} value={subject} maxLength={500} placeholder={info.placeholder} onChange={(event) => setSubject(event.target.value)} dir="auto" />
        )}
      </Field>
      <Field label={c.happened} error={errors.description} hint={c.happenedHint}>
        {(props) => (
          <Textarea {...props} value={description} maxLength={2000} className="min-h-28" onChange={(event) => setDescription(event.target.value)} dir="auto" />
        )}
      </Field>
      <Field
        label={c.evidence}
        error={errors.evidence}
        hint={c.evidenceHint}
      >
        {(props) => (
          <Textarea {...props} value={evidence} maxLength={5000} className="min-h-28" onChange={(event) => setEvidence(event.target.value)} dir="auto" />
        )}
      </Field>
      {session.status === "signed-in" && (
        <label className="flex items-start gap-3 text-sm">
          <input type="checkbox" className="mt-1 size-4 accent-[var(--accent)]" checked={anonymous} onChange={(event) => setAnonymous(event.target.checked)} />
          <span>
            <span className="font-medium text-ink">{c.anonymous}</span>
            <span className="block text-ink-muted">{c.anonymousHint}</span>
          </span>
        </label>
      )}
      <Button type="submit" size="lg" pending={pending}>
        {c.send}
      </Button>
    </form>
  );
}

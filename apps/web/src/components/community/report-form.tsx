"use client";

import { CheckCircle2 } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { ApiError, api } from "@/lib/api/client";
import type { ReportCategory, ReportCreated } from "@/lib/api/types";
import { CATEGORY } from "@/lib/community";
import { useSession } from "@/lib/session";

export function ReportForm() {
  const { session } = useSession();
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
    if (subject.trim().length < 3) found.subject = "Tell us what you are reporting.";
    if (description.trim().length < 10) found.description = "Describe what happened in a sentence or two.";
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
        setErrors({ form: "The report could not be sent." });
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
          Thank you. Your report was received.
        </p>
        <p className="text-sm text-ink-muted">
          A moderator will review it. Reports are not published until they are confirmed, and your own
          words are never published.
          {created.similar_reports > 0 &&
            ` ${created.similar_reports} other ${created.similar_reports === 1 ? "person has" : "people have"} reported the same thing.`}
        </p>
        {created.tracking_token ? (
          <Alert title="Keep this link to follow your report">
            <span className="break-all">
              This is the only way to see your report’s status, because it is not linked to an account:{" "}
              <Link className="text-accent underline" href={trackHref}>
                view report status
              </Link>
            </span>
          </Alert>
        ) : (
          <Link className="text-sm font-medium text-accent underline underline-offset-4" href={trackHref}>
            See your reports
          </Link>
        )}
      </div>
    );
  }

  const info = CATEGORY[category];
  return (
    <form onSubmit={submit} noValidate className="space-y-5">
      {errors.form && <Alert tone="danger">{errors.form}</Alert>}
      <Field label="What are you reporting?">
        {(props) => (
          <Select {...props} value={category} onChange={(event) => setCategory(event.target.value as ReportCategory)} className="w-full">
            {Object.entries(CATEGORY).map(([value, item]) => (
              <option key={value} value={value}>
                {item.label}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label={info.subjectLabel} error={errors.subject}>
        {(props) => (
          <Input {...props} value={subject} maxLength={500} placeholder={info.placeholder} onChange={(event) => setSubject(event.target.value)} dir="auto" />
        )}
      </Field>
      <Field label="What happened?" error={errors.description} hint="For example how you were contacted and what they asked for.">
        {(props) => (
          <Textarea {...props} value={description} maxLength={2000} className="min-h-28" onChange={(event) => setDescription(event.target.value)} dir="auto" />
        )}
      </Field>
      <Field
        label="Evidence (optional)"
        error={errors.evidence}
        hint="Paste the message text or other details. Only moderators can see it. Remove your own personal details first."
      >
        {(props) => (
          <Textarea {...props} value={evidence} maxLength={5000} className="min-h-28" onChange={(event) => setEvidence(event.target.value)} dir="auto" />
        )}
      </Field>
      {session.status === "signed-in" && (
        <label className="flex items-start gap-3 text-sm">
          <input type="checkbox" className="mt-1 size-4 accent-[var(--accent)]" checked={anonymous} onChange={(event) => setAnonymous(event.target.checked)} />
          <span>
            <span className="font-medium text-ink">Report anonymously</span>
            <span className="block text-ink-muted">The report will not be linked to your account. You will get a private link to follow it instead.</span>
          </span>
        </label>
      )}
      <Button type="submit" size="lg" pending={pending}>
        Send report
      </Button>
    </form>
  );
}

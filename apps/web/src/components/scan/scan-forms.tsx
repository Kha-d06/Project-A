"use client";

import { FileUp, Globe, Image as ImageIcon, Link2, MessageSquareText, QrCode, Smartphone, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useRef, useState, type FormEvent, type ReactNode } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/field";
import { ApiError, api } from "@/lib/api/client";
import type { Scan, ScanType } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatBytes } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";

export const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_MESSAGE_LENGTH = 10_000;
const MIN_MESSAGE_LENGTH = 10;

interface SubmitState {
  pending: boolean;
  error: ApiError | null;
}

function useScanSubmission(reportBase: string) {
  const router = useRouter();
  const { t } = useI18n();
  const [state, setState] = useState<SubmitState>({ pending: false, error: null });

  const submit = async (start: () => Promise<Scan>) => {
    setState({ pending: true, error: null });
    try {
      const scan = await start();
      router.push(`${reportBase}/${scan.id}`);
    } catch (error) {
      setState({
        pending: false,
        error: error instanceof ApiError ? error : new ApiError(0, "unknown", t.scan.errors.generic),
      });
    }
  };
  return { ...state, submit };
}

function SubmissionError({ error }: { error: ApiError | null }) {
  const { t } = useI18n();
  if (!error || error.code === "validation_error") return null;
  const title = error.code === "rate_limited" ? t.scan.errors.slowDown : t.scan.errors.couldNotStart;
  return (
    <Alert tone="warning" title={title}>
      {error.message}
    </Alert>
  );
}

export function UrlScanForm({
  reportBase,
  initialUrl = "",
  mode = "link",
}: {
  reportBase: string;
  initialUrl?: string;
  mode?: "link" | "website";
}) {
  const { pending, error, submit } = useScanSubmission(reportBase);
  const { t } = useI18n();
  // Prefilled (never auto-submitted) when the browser extension sends a link here.
  const [url, setUrl] = useState(initialUrl);
  const [localError, setLocalError] = useState<string>();

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!url.trim()) {
      setLocalError(t.scan.link.empty);
      return;
    }
    setLocalError(undefined);
    void submit(() => (mode === "website" ? api.scans.website(url.trim()) : api.scans.url(url.trim())));
  };

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <Field
        label={mode === "website" ? t.scan.link.websiteLabel : t.scan.link.label}
        hint={mode === "website" ? t.scan.link.websiteHint : t.scan.link.hint}
        error={localError ?? error?.fieldErrors().url}
      >
        {(props) => (
          <Input
            {...props}
            name="url"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://example.com/account/verify"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            className="font-mono text-[0.9rem]"
          />
        )}
      </Field>
      <SubmissionError error={error} />
      <Button type="submit" size="lg" pending={pending} className="w-full sm:w-auto">
        {pending ? t.scan.link.starting : mode === "website" ? t.scan.link.websiteSubmit : t.scan.link.submit}
      </Button>
    </form>
  );
}

export function MessageScanForm({ reportBase, initialText = "" }: { reportBase: string; initialText?: string }) {
  const { pending, error, submit } = useScanSubmission(reportBase);
  const { t } = useI18n();
  // Prefilled (never auto-submitted) when text is shared to Qalaa from another app.
  const [content, setContent] = useState(initialText);
  const [aiConsent, setAiConsent] = useState(false);
  const [sender, setSender] = useState("");
  const [localError, setLocalError] = useState<string>();

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (content.trim().length < MIN_MESSAGE_LENGTH) {
      setLocalError(t.scan.message.tooShort);
      return;
    }
    setLocalError(undefined);
    void submit(() => api.scans.message(content, { aiConsent, sender }));
  };

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <Field
        label={t.scan.message.label}
        hint={
          <>
            {t.scan.message.hint} {content.length > 0 && `${content.length.toLocaleString()} / 10,000`}
          </>
        }
        error={localError ?? error?.fieldErrors().content}
      >
        {(props) => (
          <Textarea
            {...props}
            name="content"
            dir="auto"
            maxLength={MAX_MESSAGE_LENGTH}
            placeholder={t.scan.message.placeholder}
            value={content}
            onChange={(event) => setContent(event.target.value)}
          />
        )}
      </Field>
      <Field label={t.extra.sender.label} hint={t.extra.sender.hint}>
        {(props) => (
          <Input
            {...props}
            name="sender"
            dir="auto"
            maxLength={60}
            placeholder={t.extra.sender.placeholder}
            value={sender}
            onChange={(event) => setSender(event.target.value)}
          />
        )}
      </Field>
      <ConsentCheckbox
        checked={aiConsent}
        onChange={setAiConsent}
        label={t.scan.message.aiConsent}
        hint={t.scan.message.aiConsentHint}
      />
      <SubmissionError error={error} />
      <Button type="submit" size="lg" pending={pending} className="w-full sm:w-auto">
        {pending ? t.scan.message.starting : t.scan.message.submit}
      </Button>
    </form>
  );
}

/** An opt-in that is off by default and explains exactly what leaves the server. */
function ConsentCheckbox({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  hint: string;
}) {
  const id = useId();
  return (
    <div className="flex items-start gap-3 rounded-control border border-line bg-surface-sunken/40 p-3">
      <input
        id={id}
        type="checkbox"
        aria-describedby={`${id}-hint`}
        className="mt-1 size-4 accent-[var(--accent)]"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      <div className="space-y-0.5">
        <label htmlFor={id} className="text-sm font-medium text-ink">
          {label}
        </label>
        <p id={`${id}-hint`} className="text-xs text-ink-muted">
          {hint}
        </p>
      </div>
    </div>
  );
}

interface UploadFormProps {
  reportBase: string;
  label: string;
  hint: string;
  submitLabel: string;
  accept?: string;
  maxBytes: number;
  /** On phones, offer the rear camera directly (used for QR codes). */
  capture?: boolean;
  start: (file: File) => Promise<Scan>;
  /** Extra controls shown above the submit button. */
  extra?: ReactNode;
}

function UploadScanForm({ reportBase, label, hint, submitLabel, accept, maxBytes, capture, start, extra }: UploadFormProps) {
  const { pending, error, submit } = useScanSubmission(reportBase);
  const { t } = useI18n();
  const [file, setFile] = useState<File | null>(null);
  const [localError, setLocalError] = useState<string>();
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const hintId = `${inputId}-hint`;
  const errorId = `${inputId}-error`;

  const choose = (candidate: File | undefined) => {
    if (!candidate) return;
    if (candidate.size === 0) {
      setLocalError(t.scan.upload.empty);
      return;
    }
    if (candidate.size > maxBytes) {
      setLocalError(t.scan.upload.tooLarge(formatBytes(maxBytes)));
      return;
    }
    setLocalError(undefined);
    setFile(candidate);
  };

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!file) {
      setLocalError(t.scan.upload.missing);
      return;
    }
    void submit(() => start(file));
  };

  const shownError = localError ?? (error?.code === "validation_error" ? error.message : undefined);

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <div className="space-y-1.5">
        <label htmlFor={inputId} className="block text-sm font-medium text-ink">
          {label}
        </label>
        <div
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            choose(event.dataTransfer.files[0]);
          }}
          className={cn(
            "relative rounded-panel border border-dashed px-6 py-10 text-center transition-colors",
            dragging ? "border-accent bg-accent-soft" : "border-line-strong bg-surface-sunken/50",
            shownError && "border-danger",
          )}
        >
          {file ? (
            <div className="flex items-center justify-center gap-3">
              <FileUp aria-hidden className="size-5 text-accent" />
              <div className="min-w-0 text-start">
                <p className="truncate font-mono text-sm text-ink">{file.name}</p>
                <p className="text-sm text-ink-muted">{formatBytes(file.size)}</p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setFile(null);
                  if (inputRef.current) inputRef.current.value = "";
                }}
                className="grid size-8 place-items-center rounded-control text-ink-faint hover:bg-surface hover:text-ink"
                aria-label={t.scan.upload.remove}
              >
                <X aria-hidden className="size-4" />
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <FileUp aria-hidden className="mx-auto size-6 text-ink-faint" />
              <p className="text-sm text-ink">
                {t.scan.upload.drop}{" "}
                <button
                  type="button"
                  onClick={() => inputRef.current?.click()}
                  className="font-medium text-accent underline-offset-4 hover:underline"
                >
                  {capture ? t.scan.upload.choosePhoto : t.scan.upload.choose}
                </button>
              </p>
            </div>
          )}
          <input
            ref={inputRef}
            id={inputId}
            type="file"
            name="file"
            accept={accept}
            capture={capture ? "environment" : undefined}
            className="sr-only"
            aria-describedby={shownError ? errorId : hintId}
            aria-invalid={Boolean(shownError)}
            onChange={(event) => choose(event.target.files?.[0])}
          />
        </div>
        {shownError ? (
          <p id={errorId} className="text-sm text-danger">
            {shownError}
          </p>
        ) : (
          <p id={hintId} className="text-sm text-ink-muted">
            {hint}
          </p>
        )}
      </div>
      {extra}
      <SubmissionError error={error?.code === "validation_error" ? null : error} />
      <Button type="submit" size="lg" pending={pending} className="w-full sm:w-auto">
        {pending ? t.scan.upload.uploading : submitLabel}
      </Button>
    </form>
  );
}

export const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
export const MAX_APK_BYTES = 100 * 1024 * 1024;

export function FileScanForm({ reportBase }: { reportBase: string }) {
  const { t } = useI18n();
  const [virustotalConsent, setVirustotalConsent] = useState(false);
  return (
    <UploadScanForm
      reportBase={reportBase}
      label={t.scan.file.label}
      submitLabel={t.scan.file.submit}
      maxBytes={MAX_FILE_BYTES}
      hint={t.scan.file.hint(formatBytes(MAX_FILE_BYTES))}
      start={(file) => api.scans.file(file, { virustotalConsent })}
      extra={
        <ConsentCheckbox
          checked={virustotalConsent}
          onChange={setVirustotalConsent}
          label={t.scan.file.vtConsent}
          hint={t.scan.file.vtConsentHint}
        />
      }
    />
  );
}

export function QrScanForm({ reportBase }: { reportBase: string }) {
  const { t } = useI18n();
  return (
    <UploadScanForm
      reportBase={reportBase}
      label={t.scan.qr.label}
      submitLabel={t.scan.qr.submit}
      accept="image/png,image/jpeg,image/gif,image/webp,image/bmp"
      capture
      maxBytes={MAX_IMAGE_BYTES}
      hint={t.scan.qr.hint}
      start={api.scans.qr}
    />
  );
}

export function ApkScanForm({ reportBase }: { reportBase: string }) {
  const { t } = useI18n();
  return (
    <UploadScanForm
      reportBase={reportBase}
      label={t.scan.apk.label}
      submitLabel={t.scan.apk.submit}
      accept=".apk,application/vnd.android.package-archive"
      maxBytes={MAX_APK_BYTES}
      hint={t.scan.apk.hint(formatBytes(MAX_APK_BYTES))}
      start={api.scans.apk}
    />
  );
}

export function ScreenshotScanForm({ reportBase }: { reportBase: string }) {
  const { t } = useI18n();
  const [aiConsent, setAiConsent] = useState(false);
  return (
    <UploadScanForm
      reportBase={reportBase}
      label={t.scan.screenshot.label}
      submitLabel={t.scan.screenshot.submit}
      accept="image/png,image/jpeg,image/webp,image/gif,image/bmp"
      maxBytes={MAX_IMAGE_BYTES}
      hint={t.scan.screenshot.hint}
      start={(image) => api.scans.screenshot(image, { aiConsent })}
      extra={
        <ConsentCheckbox
          checked={aiConsent}
          onChange={setAiConsent}
          label={t.scan.screenshot.aiConsent}
          hint={t.scan.screenshot.aiConsentHint}
        />
      }
    />
  );
}

/** Order and icons of the scanner tabs; labels and descriptions come from the dictionary. */
export const SCAN_TABS: { type: ScanType; icon: typeof Link2 }[] = [
  { type: "url", icon: Link2 },
  { type: "message", icon: MessageSquareText },
  { type: "file", icon: FileUp },
  { type: "qr", icon: QrCode },
  { type: "website", icon: Globe },
  { type: "apk", icon: Smartphone },
  { type: "screenshot", icon: ImageIcon },
];

"use client";

import { FileUp, Globe, Link2, MessageSquareText, QrCode, Smartphone, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useRef, useState, type FormEvent } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/field";
import { ApiError, api } from "@/lib/api/client";
import type { Scan, ScanType } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatBytes } from "@/lib/format";

export const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_MESSAGE_LENGTH = 10_000;
const MIN_MESSAGE_LENGTH = 10;

interface SubmitState {
  pending: boolean;
  error: ApiError | null;
}

function useScanSubmission(reportBase: string) {
  const router = useRouter();
  const [state, setState] = useState<SubmitState>({ pending: false, error: null });

  const submit = async (start: () => Promise<Scan>) => {
    setState({ pending: true, error: null });
    try {
      const scan = await start();
      router.push(`${reportBase}/${scan.id}`);
    } catch (error) {
      setState({
        pending: false,
        error: error instanceof ApiError ? error : new ApiError(0, "unknown", "Something went wrong."),
      });
    }
  };
  return { ...state, submit };
}

function SubmissionError({ error }: { error: ApiError | null }) {
  if (!error || error.code === "validation_error") return null;
  const title = error.code === "rate_limited" ? "Please slow down" : "The scan could not start";
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
  // Prefilled (never auto-submitted) when the browser extension sends a link here.
  const [url, setUrl] = useState(initialUrl);
  const [localError, setLocalError] = useState<string>();

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!url.trim()) {
      setLocalError("Enter a link to check.");
      return;
    }
    setLocalError(undefined);
    void submit(() => (mode === "website" ? api.scans.website(url.trim()) : api.scans.url(url.trim())));
  };

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <Field
        label={mode === "website" ? "Website address" : "Link to check"}
        hint={
          mode === "website"
            ? "SENTINEL fetches the page from its own server and reads it as text, without running its scripts. DNS records are checked too."
            : "Paste the full address. SENTINEL checks it from its own server; your browser never opens it."
        }
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
        {pending ? "Starting scan" : mode === "website" ? "Analyse website" : "Check link"}
      </Button>
    </form>
  );
}

export function MessageScanForm({ reportBase }: { reportBase: string }) {
  const { pending, error, submit } = useScanSubmission(reportBase);
  const [content, setContent] = useState("");
  const [localError, setLocalError] = useState<string>();

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (content.trim().length < MIN_MESSAGE_LENGTH) {
      setLocalError("Paste the full message so there is enough text to analyse.");
      return;
    }
    setLocalError(undefined);
    void submit(() => api.scans.message(content));
  };

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <Field
        label="Message text"
        hint={
          <>
            Paste an SMS, WhatsApp message, email, job offer or payment request, in English or
            Arabic. The text is analysed and then discarded; only the first 80 characters are
            kept as a label. {content.length > 0 && `${content.length.toLocaleString()} / 10,000`}
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
            placeholder="Your parcel could not be delivered. Pay the 1.99 redelivery fee within 24 hours at…"
            value={content}
            onChange={(event) => setContent(event.target.value)}
          />
        )}
      </Field>
      <SubmissionError error={error} />
      <Button type="submit" size="lg" pending={pending} className="w-full sm:w-auto">
        {pending ? "Starting analysis" : "Analyse message"}
      </Button>
    </form>
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
}

function UploadScanForm({ reportBase, label, hint, submitLabel, accept, maxBytes, capture, start }: UploadFormProps) {
  const { pending, error, submit } = useScanSubmission(reportBase);
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
      setLocalError("That file is empty, so there is nothing to scan.");
      return;
    }
    if (candidate.size > maxBytes) {
      setLocalError(`Files larger than ${formatBytes(maxBytes)} cannot be scanned.`);
      return;
    }
    setLocalError(undefined);
    setFile(candidate);
  };

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!file) {
      setLocalError("Choose a file to scan.");
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
                aria-label="Remove selected file"
              >
                <X aria-hidden className="size-4" />
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <FileUp aria-hidden className="mx-auto size-6 text-ink-faint" />
              <p className="text-sm text-ink">
                Drop a file here, or{" "}
                <button
                  type="button"
                  onClick={() => inputRef.current?.click()}
                  className="font-medium text-accent underline-offset-4 hover:underline"
                >
                  {capture ? "choose or take a photo" : "choose one"}
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
      <SubmissionError error={error?.code === "validation_error" ? null : error} />
      <Button type="submit" size="lg" pending={pending} className="w-full sm:w-auto">
        {pending ? "Uploading" : submitLabel}
      </Button>
    </form>
  );
}

export const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
export const MAX_APK_BYTES = 100 * 1024 * 1024;

export function FileScanForm({ reportBase }: { reportBase: string }) {
  return (
    <UploadScanForm
      reportBase={reportBase}
      label="File to scan"
      submitLabel="Scan file"
      maxBytes={MAX_FILE_BYTES}
      hint={`Up to ${formatBytes(MAX_FILE_BYTES)}. The file is inspected without being opened or run, kept in isolated storage only while the scan runs, and then deleted. It is never sent to a third-party service.`}
      start={api.scans.file}
    />
  );
}

export function QrScanForm({ reportBase }: { reportBase: string }) {
  return (
    <UploadScanForm
      reportBase={reportBase}
      label="Photo or screenshot of the QR code"
      submitLabel="Check QR code"
      accept="image/png,image/jpeg,image/gif,image/webp,image/bmp"
      capture
      maxBytes={MAX_IMAGE_BYTES}
      hint="SENTINEL reads the code and checks where it leads from its own server. The link is never opened on your device, and the image is deleted after the scan."
      start={api.scans.qr}
    />
  );
}

export function ApkScanForm({ reportBase }: { reportBase: string }) {
  return (
    <UploadScanForm
      reportBase={reportBase}
      label="Android app file (.apk)"
      submitLabel="Analyse app"
      accept=".apk,application/vnd.android.package-archive"
      maxBytes={MAX_APK_BYTES}
      hint={`Up to ${formatBytes(MAX_APK_BYTES)}. The app is inspected without being installed or run: permissions, components, embedded addresses and known malware. It is deleted after the scan.`}
      start={api.scans.apk}
    />
  );
}

export const SCAN_TABS: { type: ScanType; label: string; icon: typeof Link2; blurb: string }[] = [
  {
    type: "url",
    label: "Link",
    icon: Link2,
    blurb: "Reputation, redirects, certificate, domain age and look-alike domains.",
  },
  {
    type: "message",
    label: "Message",
    icon: MessageSquareText,
    blurb: "Scam and phishing language in English and Arabic, plus the links inside.",
  },
  {
    type: "file",
    label: "File",
    icon: FileUp,
    blurb: "True file type, disguises, macros, signature rules, archive tricks and known malware.",
  },
  {
    type: "qr",
    label: "QR code",
    icon: QrCode,
    blurb: "Reads a QR code from a photo and checks where it leads or what payment it requests.",
  },
  {
    type: "website",
    label: "Website",
    icon: Globe,
    blurb: "Everything the link scan does, plus DNS and a reading of the page: forms, scripts and imitation of brands.",
  },
  {
    type: "apk",
    label: "Android app",
    icon: Smartphone,
    blurb: "Permissions, components, embedded addresses, known malware and imitation of popular apps.",
  },
];

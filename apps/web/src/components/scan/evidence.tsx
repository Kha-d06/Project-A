import { formatDateTime } from "@/lib/format";

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

/**
 * Evidence is untrusted data from the scanned item: it may contain malicious URLs
 * or markup. It is rendered as plain text and never as a link.
 */

const LABELS: Record<string, string> = {
  matched: "Matched indicator",
  listed_by: "Listed by",
  threat: "Threat type",
  tags: "Tags",
  first_seen: "First reported",
  last_seen: "Last seen in feed",
  reference: "Feed reference",
  matched_text: "Matched text",
  link: "Link",
  displayed_as: "Displayed as",
  actual_domain: "Actual domain",
  actual_host: "Actual destination",
  imitates: "Imitates",
  resembles: "Resembles",
  domain: "Domain",
  registered: "Registered",
  host: "Host",
  file_name: "File name",
  detected_type: "Detected as",
  expanded_bytes: "Expanded size",
  compression_ratio: "Compression ratio",
  entries: "Entries",
  signature: "Signature",
};

function label(key: string): string {
  return LABELS[key] ?? key.replaceAll("_", " ").replace(/^\w/, (c) => c.toUpperCase());
}

function display(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join("\n");
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (value && typeof value === "object") return JSON.stringify(value);
  if (typeof value === "string" && ISO_TIMESTAMP.test(value)) return formatDateTime(value);
  return String(value);
}

export function EvidenceList({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence).filter(([, value]) => value !== null && value !== "");
  if (entries.length === 0) return null;
  return (
    <dl className="grid gap-x-4 gap-y-1.5 rounded-control bg-surface-sunken px-3 py-2.5 text-sm sm:grid-cols-[10rem_1fr]">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-ink-faint">{label(key)}</dt>
          <dd className="font-mono text-[0.8rem] break-all whitespace-pre-wrap text-ink" dir="auto">
            {display(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

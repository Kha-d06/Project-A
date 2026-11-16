import type { Scan } from "@/lib/api/types";
import { formatBytes } from "@/lib/format";

interface Hop {
  url: string;
  status: number | null;
}

function asHops(value: unknown): Hop[] {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (hop): hop is Hop => typeof hop === "object" && hop !== null && typeof hop.url === "string",
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 px-5 py-3 sm:grid-cols-[11rem_1fr] sm:gap-4">
      <dt className="text-sm text-ink-faint">{label}</dt>
      <dd className="min-w-0 font-mono text-[0.8rem] break-all text-ink">{children}</dd>
    </div>
  );
}

function UrlDetails({ details }: { details: Record<string, unknown> }) {
  const hops = asHops(details.redirect_chain);
  const tls = details.tls as { issuer?: string; valid_until?: string } | undefined;
  return (
    <dl className="divide-y divide-line">
      <Row label="Submitted">{String(details.submitted_url ?? "")}</Row>
      {details.final_url !== details.submitted_url && details.final_url !== undefined && (
        <Row label="Final destination">{String(details.final_url)}</Row>
      )}
      {hops.length > 1 && (
        <Row label="Redirect chain">
          <ol className="space-y-1.5">
            {hops.map((hop, index) => (
              <li key={`${hop.url}-${index}`} className="flex gap-2">
                <span className="w-9 shrink-0 text-ink-faint">{hop.status ?? "—"}</span>
                <span>{hop.url}</span>
              </li>
            ))}
          </ol>
        </Row>
      )}
      {typeof details.domain_registered_at === "string" && (
        <Row label="Domain registered">{details.domain_registered_at.slice(0, 10)}</Row>
      )}
      {tls && (
        <Row label="Certificate">
          {tls.issuer ?? "Unknown issuer"}
          {tls.valid_until && `, valid until ${tls.valid_until}`}
        </Row>
      )}
    </dl>
  );
}

function FileDetails({ details }: { details: Record<string, unknown> }) {
  const archive = details.archive as { entries?: number; names?: string[] } | undefined;
  return (
    <dl className="divide-y divide-line">
      <Row label="File name">{String(details.file_name ?? "")}</Row>
      <Row label="Detected type">{String(details.detected_type ?? "")}</Row>
      {typeof details.size_bytes === "number" && <Row label="Size">{formatBytes(details.size_bytes)}</Row>}
      <Row label="SHA-256">{String(details.sha256 ?? "")}</Row>
      {archive && (
        <Row label={`Archive (${archive.entries ?? 0} entries)`}>
          <ul className="space-y-1">
            {(archive.names ?? []).map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </Row>
      )}
    </dl>
  );
}

function MessageDetails({ details }: { details: Record<string, unknown> }) {
  const indicators = (details.indicators ?? {}) as Record<string, string[] | undefined>;
  const groups = [
    { key: "urls", label: "Links found" },
    { key: "emails", label: "Email addresses" },
    { key: "phone_numbers", label: "Phone numbers" },
  ];
  const present = groups.filter((group) => (indicators[group.key] ?? []).length > 0);
  if (present.length === 0) {
    return <p className="px-5 py-4 text-sm text-ink-muted">No links, email addresses or phone numbers were found.</p>;
  }
  return (
    <dl className="divide-y divide-line">
      {present.map((group) => (
        <Row key={group.key} label={group.label}>
          <ul className="space-y-1">
            {(indicators[group.key] ?? []).map((value) => (
              <li key={value}>{value}</li>
            ))}
          </ul>
        </Row>
      ))}
    </dl>
  );
}

export function ScanDetails({ scan }: { scan: Scan }) {
  if (scan.scan_type === "url") return <UrlDetails details={scan.details} />;
  if (scan.scan_type === "file") return <FileDetails details={scan.details} />;
  return <MessageDetails details={scan.details} />;
}

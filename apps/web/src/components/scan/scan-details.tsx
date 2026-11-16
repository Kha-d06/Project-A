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
  const pe = details.pe as
    | { kind?: string; imports?: number; has_signature?: boolean; compiled?: string | null }
    | undefined;
  return (
    <dl className="divide-y divide-line">
      <Row label="File name">{String(details.file_name ?? "")}</Row>
      <Row label="Detected type">{String(details.detected_type ?? "")}</Row>
      {typeof details.size_bytes === "number" && <Row label="Size">{formatBytes(details.size_bytes)}</Row>}
      <Row label="SHA-256">{String(details.sha256 ?? "")}</Row>
      {pe && (
        <Row label="Windows program">
          {`${pe.kind ?? "program"}, ${pe.imports ?? 0} imported functions, ${pe.has_signature ? "has a digital signature (not verified)" : "not digitally signed"}`}
          {pe.compiled && `, built ${pe.compiled.slice(0, 10)}`}
        </Row>
      )}
      {typeof details.macro_modules !== "undefined" && (
        <Row label="Macros">
          {`${String(details.macro_modules)} module(s)${details.runs_automatically ? ", runs automatically" : ""}`}
          {Array.isArray(details.suspicious_keywords) && details.suspicious_keywords.length > 0 &&
            `; uses ${(details.suspicious_keywords as string[]).join(", ")}`}
        </Row>
      )}
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

function List({ items }: { items: string[] }) {
  return (
    <ul className="space-y-1">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

const QR_KIND_LABEL: Record<string, string> = {
  url: "Web link",
  upi_payment: "UPI payment request",
  crypto_payment: "Cryptocurrency payment request",
  merchant_payment: "Merchant payment code (EMV)",
  wifi: "Wi-Fi network",
  contact_action: "Call, text or email",
  contact_card: "Contact card",
  text: "Plain text",
};

const QR_FIELDS: [string, string][] = [
  ["payee_name", "Payee"],
  ["payee_address", "Payee address"],
  ["merchant_name", "Merchant"],
  ["merchant_city", "City"],
  ["network", "Network"],
  ["address", "Address"],
  ["amount", "Amount"],
  ["network_name", "Wi-Fi network"],
  ["security", "Wi-Fi security"],
  ["target", "Target"],
];

function QrDetails({ scan }: { scan: Scan }) {
  const details = scan.details;
  if (typeof details.qr_content !== "string") {
    return <p className="px-5 py-4 text-sm text-ink-muted">No QR code was read from the image.</p>;
  }
  if (details.qr_kind === "url") {
    return (
      <>
        <dl className="divide-y divide-line">
          <Row label="Content type">{QR_KIND_LABEL.url}</Row>
        </dl>
        <UrlDetails details={details} />
      </>
    );
  }
  return (
    <dl className="divide-y divide-line">
      <Row label="Content type">{QR_KIND_LABEL[String(details.qr_kind)] ?? "Unknown"}</Row>
      {QR_FIELDS.filter(([key]) => typeof details[key] === "string" && details[key]).map(([key, label]) => (
        <Row key={key} label={label}>
          {String(details[key])}
        </Row>
      ))}
      <Row label="Decoded content">
        <span className="whitespace-pre-wrap">{details.qr_content}</span>
      </Row>
    </dl>
  );
}

interface PageSummary {
  title?: string;
  forms?: { action: string; method: string; asks_for_password: boolean; asks_for_card: boolean }[];
  external_script_hosts?: string[];
  hidden_frames?: string[];
  security_headers?: Record<string, boolean>;
}

function WebsiteDetails({ details }: { details: Record<string, unknown> }) {
  const page = details.page as PageSummary | undefined;
  const dns = (details.dns ?? {}) as Record<string, string[]>;
  return (
    <>
      <UrlDetails details={details} />
      <dl className="divide-y divide-line border-t border-line">
        {page?.title !== undefined && <Row label="Page title">{page.title || "(none)"}</Row>}
        {page?.forms && page.forms.length > 0 && (
          <Row label="Forms">
            <ul className="space-y-1">
              {page.forms.map((form, index) => (
                <li key={`${form.action}-${index}`}>
                  {form.method.toUpperCase()} {form.action}
                  {form.asks_for_password && " · asks for a password"}
                  {form.asks_for_card && " · asks for card details"}
                </li>
              ))}
            </ul>
          </Row>
        )}
        {page?.external_script_hosts && page.external_script_hosts.length > 0 && (
          <Row label="Scripts loaded from">
            <List items={page.external_script_hosts} />
          </Row>
        )}
        {page?.security_headers && (
          <Row label="Security headers">
            <List
              items={Object.entries(page.security_headers).map(
                ([header, present]) => `${header}: ${present ? "present" : "missing"}`,
              )}
            />
          </Row>
        )}
        {Object.entries(dns)
          .filter(([, values]) => values.length > 0)
          .map(([type, values]) => (
            <Row key={type} label={`DNS ${type}`}>
              <List items={values} />
            </Row>
          ))}
      </dl>
    </>
  );
}

interface AppFacts {
  package?: string;
  app_name?: string;
  version?: string;
  min_sdk?: string;
  target_sdk?: number;
  exported_components?: string[];
}

function ApkDetails({ details }: { details: Record<string, unknown> }) {
  const app = details.app as AppFacts | undefined;
  const permissions = (details.sensitive_permissions ?? {}) as Record<string, string>;
  const hosts = (details.embedded_hosts ?? []) as string[];
  const sdks = (details.sdks ?? []) as string[];
  return (
    <dl className="divide-y divide-line">
      <Row label="File name">{String(details.file_name ?? "")}</Row>
      {app && (
        <>
          <Row label="App name">{app.app_name || "(not set)"}</Row>
          <Row label="Package">{app.package}</Row>
          <Row label="Version">{app.version ?? "unknown"}</Row>
          <Row label="Android versions">
            {`Minimum SDK ${app.min_sdk ?? "?"}, targets SDK ${app.target_sdk ?? "?"}`}
          </Row>
        </>
      )}
      {Object.keys(permissions).length > 0 && (
        <Row label="Sensitive permissions">
          <ul className="space-y-1.5 font-sans text-sm">
            {Object.entries(permissions).map(([name, meaning]) => (
              <li key={name}>
                <span className="font-mono text-[0.8rem]">{name}</span>
                <span className="block text-ink-muted">{meaning}</span>
              </li>
            ))}
          </ul>
        </Row>
      )}
      {app?.exported_components && app.exported_components.length > 0 && (
        <Row label="Exposed to other apps">
          <List items={app.exported_components} />
        </Row>
      )}
      {hosts.length > 0 && (
        <Row label="Addresses in the code">
          <List items={hosts} />
        </Row>
      )}
      {sdks.length > 0 && (
        <Row label="Third-party SDKs">
          <List items={sdks} />
        </Row>
      )}
      <Row label="SHA-256">{String(details.sha256 ?? "")}</Row>
    </dl>
  );
}

export function ScanDetails({ scan }: { scan: Scan }) {
  switch (scan.scan_type) {
    case "url":
      return <UrlDetails details={scan.details} />;
    case "file":
      return <FileDetails details={scan.details} />;
    case "qr":
      return <QrDetails scan={scan} />;
    case "website":
      return <WebsiteDetails details={scan.details} />;
    case "apk":
      return <ApkDetails details={scan.details} />;
    default:
      return <MessageDetails details={scan.details} />;
  }
}

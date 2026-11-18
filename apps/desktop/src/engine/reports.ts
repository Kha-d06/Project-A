/**
 * Reports for records and audits: a hardware inventory, a security audit and a
 * performance snapshot, as JSON, CSV or a self-contained HTML page (which the app
 * also prints to PDF). Everything comes from this computer; nothing is uploaded.
 */

export type ReportKind = "inventory" | "security" | "performance";
export type ReportFormat = "json" | "csv" | "html" | "pdf";

export interface ReportSection {
  title: string;
  /** Key/value facts, or a table (columns + rows). */
  facts?: [string, string][];
  table?: { columns: string[]; rows: (string | number | null)[][] };
}

export interface Report {
  kind: ReportKind;
  title: string;
  generatedAt: string;
  computer: string;
  sections: ReportSection[];
}

export function toJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

function csvCell(value: string | number | null): string {
  const text = value === null ? "" : String(value);
  // Quote, and neutralise leading formula characters so spreadsheets do not execute them.
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n]/.test(safe) || safe !== text ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** One CSV: section, then each fact as "key,value" or each table row. */
export function toCsv(report: Report): string {
  const lines: string[] = [[report.title, report.generatedAt, report.computer].map(csvCell).join(",")];
  for (const section of report.sections) {
    lines.push("", csvCell(section.title));
    for (const [key, value] of section.facts ?? []) lines.push([key, value].map(csvCell).join(","));
    if (section.table) {
      lines.push(section.table.columns.map(csvCell).join(","));
      for (const row of section.table.rows) lines.push(row.map(csvCell).join(","));
    }
  }
  return lines.join("\r\n") + "\r\n";
}

function escape(text: string | number | null): string {
  return String(text ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/** A printable, self-contained page (no scripts, no external resources). */
export function toHtml(report: Report): string {
  const sections = report.sections
    .map((s) => {
      const facts = s.facts?.length ? `<dl>${s.facts.map(([k, v]) => `<dt>${escape(k)}</dt><dd>${escape(v)}</dd>`).join("")}</dl>` : "";
      const table = s.table
        ? `<table><thead><tr>${s.table.columns.map((c) => `<th>${escape(c)}</th>`).join("")}</tr></thead><tbody>${s.table.rows
            .map((r) => `<tr>${r.map((c) => `<td>${escape(c)}</td>`).join("")}</tr>`)
            .join("")}</tbody></table>`
        : "";
      return `<section><h2>${escape(s.title)}</h2>${facts}${table}</section>`;
    })
    .join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${escape(report.title)}</title><style>
body{font:13px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#121726;margin:40px;}
header{border-bottom:2px solid #8a560b;padding-bottom:12px;margin-bottom:20px}
.brand{font:700 11px/1 ui-monospace,monospace;letter-spacing:.2em;color:#8a560b}
h1{font-size:24px;margin:8px 0 4px} .meta{color:#4b5164}
h2{font-size:15px;margin:24px 0 8px;border-bottom:1px solid #e4ddcf;padding-bottom:4px}
dl{display:grid;grid-template-columns:220px 1fr;gap:4px 16px;margin:0} dt{color:#4b5164} dd{margin:0}
table{border-collapse:collapse;width:100%;font-size:12px} th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #e4ddcf;vertical-align:top}
th{color:#4b5164;font-weight:600} section{break-inside:avoid}
footer{margin-top:28px;color:#5f6577;font-size:11px}
</style></head><body><header><div class="brand">QALAA DESKTOP</div><h1>${escape(report.title)}</h1>
<div class="meta">${escape(report.computer)} · ${escape(new Date(report.generatedAt).toUTCString())}</div></header>${sections}
<footer>Generated on this computer by Qalaa Desktop. It reflects only what the listed checks could read at that moment.</footer></body></html>`;
}

export function render(report: Report, format: Exclude<ReportFormat, "pdf">): string {
  return format === "json" ? toJson(report) : format === "csv" ? toCsv(report) : toHtml(report);
}

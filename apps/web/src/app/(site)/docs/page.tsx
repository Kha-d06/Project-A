import type { Metadata } from "next";

import { ProsePage } from "@/components/site/prose";

export const metadata: Metadata = { title: "Documentation" };

const ENDPOINTS = [
  ["POST", "/api/v1/scans/url", "Start a link scan. Body: { \"url\": \"…\" }"],
  ["POST", "/api/v1/scans/message", "Start a message analysis. Body: { \"content\": \"…\" }"],
  ["POST", "/api/v1/scans/file", "Start a file scan. Multipart form with a file field."],
  ["POST", "/api/v1/scans/qr", "Decode and check a QR code image. Multipart form, up to 10 MB."],
  ["POST", "/api/v1/scans/website", "Link checks plus DNS and a static reading of the page."],
  ["POST", "/api/v1/scans/apk", "Static analysis of an Android app. Multipart form, up to 100 MB."],
  ["POST", "/api/v1/scans/{id}/explanation", "Optional AI explanation of a finished scan, if configured."],
  ["GET", "/api/v1/scans/{id}", "Fetch a scan. Poll until status is no longer queued or processing."],
  ["GET", "/api/v1/scans/history", "Your saved scans, filterable by type, risk, status and date."],
  ["GET", "/api/v1/intelligence/{domain|ip|hash}/{value}", "Look up a domain, IP address or SHA-256 in the threat feeds."],
  ["POST", "/api/v1/reports", "Report a scam (reviewed by a moderator before it is used)."],
  ["GET", "/api/v1/system/providers", "Which checks this server can perform right now."],
];

export default function DocsPage() {
  return (
    <ProsePage
      title="Documentation"
      intro="How scans work and how to use the SENTINEL API."
    >
      <section>
        <h2>Reading a report</h2>
        <p>
          Each report has a verdict, the findings that led to it, the checks that ran (and those
          that could not), recommended next steps, and the limits of the scan. A finding marked as a
          <strong> confirmed threat</strong> comes from threat intelligence or a malware signature. Other
          findings are warning signs that call for caution but do not prove anything on their own.
        </p>
        <p>
          A scan is <strong>inconclusive</strong> when none of the reputation checks it depends on
          could run, for example because the threat feed has not synchronised yet.
        </p>
      </section>
      <section>
        <h2>API</h2>
        <p>
          The API is versioned under <code className="font-mono text-ink">/api/v1</code> and returns
          JSON. Errors share one shape:{" "}
          <code className="font-mono text-ink">{`{ "error": { "code", "message", "details" } }`}</code>.
          Scans are processed in the background: a submission returns immediately with status{" "}
          <code className="font-mono text-ink">queued</code>.
        </p>
        <div className="overflow-x-auto rounded-panel border border-line">
          <table className="w-full text-start text-sm">
            <thead className="bg-surface-sunken text-ink">
              <tr>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Method</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Path</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {ENDPOINTS.map(([method, path, purpose]) => (
                <tr key={path}>
                  <td className="px-4 py-2.5 font-mono text-ink">{method}</td>
                  <td className="px-4 py-2.5 font-mono whitespace-nowrap text-ink">{path}</td>
                  <td className="px-4 py-2.5">{purpose}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          The complete reference, with request and response schemas, is generated from the code and
          served at{" "}
          {/* A full page load on purpose: this is the API's own HTML, not a Next.js page. */}
          {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
          <a href="/api/v1/docs">/api/v1/docs</a>.
        </p>
      </section>
      <section>
        <h2>Using the API from your own code</h2>
        <p>
          Every endpoint above works without an account. To save scans to your history from a
          script, create a personal API key under Settings and send it with each request:
        </p>
        <pre
          tabIndex={0}
          aria-label="Example request"
          className="overflow-x-auto rounded-control bg-surface-sunken p-4 font-mono text-xs text-ink"
        >
{`curl -X POST https://your-sentinel.example/api/v1/scans/url \
  -H "Authorization: Bearer snt_..." \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/login"}'`}
        </pre>
        <p>
          Keys can scan, read your scan history and look up intelligence. They cannot change your
          password, export or delete your account, manage keys, or use moderator and administrator
          functions, so a leaked key cannot take over your account. Revoke a key in Settings at any
          time. Send <code className="font-mono text-ink">Accept-Language: ar</code> to receive verdict
          summaries and advice in Arabic.
        </p>
      </section>
      <section>
        <h2>Rate limits</h2>
        <p>
          To keep the service available, each visitor or account can start 60 scans per hour, of
          which up to 20 can be file scans. Limits are the same for everyone and are not tied to any
          plan. When a limit is reached the API answers with status 429 and a{" "}
          <code className="font-mono text-ink">Retry-After</code> header.
        </p>
      </section>
    </ProsePage>
  );
}

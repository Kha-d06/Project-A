import { render, screen, waitFor } from "@testing-library/react";

import { ToastProvider } from "@/components/ui/toast";
import { SessionProvider } from "@/lib/session";
import { jsonResponse, makeScan } from "@/test/fixtures";

import { ScanReport } from "./scan-report";

const signedOut = jsonResponse({ user: null, csrf_token: null });

function renderReport() {
  return render(
    <SessionProvider>
      <ToastProvider>
        <ScanReport scanId={makeScan().id} backHref="/scan" newScanHref="/scan" />
      </ToastProvider>
    </SessionProvider>,
  );
}

/** Route the session probe and scan fetches to separate canned responses. */
function serve(scans: Response[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.endsWith("/auth/session")) return signedOut.clone();
      const next = scans.length > 1 ? scans.shift() : scans[0];
      return next!.clone();
    }),
  );
}

describe("ScanReport", () => {
  it("shows honest progress while scanning, then the verdict", async () => {
    serve([
      jsonResponse(makeScan({ status: "processing", risk: null, completed_at: null })),
      jsonResponse(
        makeScan({
          risk: "known_malicious",
          confidence: "high",
          summary: "This link is a known threat.",
          findings: [
            {
              severity: "critical",
              category: "threat_intelligence",
              title: "This exact link is listed by URLhaus",
              explanation: "Reported as distributing malware.",
              evidence: { matched: "http://bad.example/<script>alert(1)</script>" },
              source: "URLhaus (abuse.ch)",
            },
          ],
        }),
      ),
    ]);
    renderReport();

    expect(await screen.findByText(/Running link checks/)).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();

    expect(await screen.findByRole("heading", { name: "Known threat" }, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText("High confidence")).toBeInTheDocument();
    // Untrusted evidence is shown as text, never as markup or a clickable link.
    expect(screen.getByText("http://bad.example/<script>alert(1)</script>")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /bad\.example/ })).not.toBeInTheDocument();
  });

  it("presents a clean result as no known threat, with its limits", async () => {
    serve([jsonResponse(makeScan())]);
    renderReport();
    expect(await screen.findByRole("heading", { name: "No known threat detected" })).toBeInTheDocument();
    expect(screen.getByText(/not proof/)).toBeInTheDocument();
    expect(screen.getByText("Page content was not downloaded or inspected.")).toBeInTheDocument();
    expect(screen.queryByText(/\bsafe\b/i)).not.toBeInTheDocument();
  });

  it("lists unavailable checks on an inconclusive result", async () => {
    serve([
      jsonResponse(
        makeScan({
          status: "inconclusive",
          risk: "inconclusive",
          confidence: "low",
          checks: [
            {
              key: "antivirus",
              label: "Antivirus signatures",
              provider: "ClamAV",
              status: "unavailable",
              detail: "No ClamAV service is configured.",
              core: true,
              finished_at: "2026-11-16T10:00:01Z",
            },
          ],
        }),
      ),
    ]);
    renderReport();
    expect(await screen.findByRole("heading", { name: "Inconclusive" })).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("No ClamAV service is configured.")).toBeInTheDocument();
  });

  it("explains a failed scan without inventing a verdict", async () => {
    serve([jsonResponse(makeScan({ status: "failed", risk: null, error: "The scan took too long and was stopped." }))]);
    renderReport();
    expect(await screen.findByRole("heading", { name: "The scan could not finish" })).toBeInTheDocument();
    expect(screen.getByText(/treat the item as unchecked/)).toBeInTheDocument();
    expect(screen.queryByText("Checks performed")).not.toBeInTheDocument();
  });

  it("handles a missing report", async () => {
    serve([jsonResponse({ error: { code: "scan_not_found", message: "Gone" } }, 404)]);
    renderReport();
    await waitFor(() => expect(screen.getByText("This report is not available")).toBeInTheDocument());
  });
});

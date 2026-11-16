import { render, screen } from "@testing-library/react";

import { RiskBadge } from "./risk-badge";

describe("RiskBadge", () => {
  it.each([
    ["known_malicious", "Known threat"],
    ["suspicious", "Suspicious"],
    ["no_known_threat", "No known threat"],
    ["inconclusive", "Inconclusive"],
  ] as const)("labels %s in words, not only colour", (risk, label) => {
    render(<RiskBadge risk={risk} status="completed" />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("shows progress instead of a verdict while a scan runs", () => {
    render(<RiskBadge risk={null} status="processing" />);
    expect(screen.getByText("Scanning")).toBeInTheDocument();
  });

  it("shows failure without a risk level", () => {
    render(<RiskBadge risk={null} status="failed" />);
    expect(screen.getByText("Scan failed")).toBeInTheDocument();
  });
});

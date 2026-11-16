import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { jsonResponse, makeScan } from "@/test/fixtures";

import { AiExplanation } from "./ai-explanation";

function serve(aiStatus: "active" | "not_configured", explanation?: Response) {
  const fetchMock = vi.fn(async (url: string) => {
    if (url.endsWith("/system/providers")) {
      return jsonResponse([{ key: "ai", name: "AI", purpose: "", status: aiStatus, detail: "", shares_data: "" }]);
    }
    return explanation!.clone();
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("AiExplanation", () => {
  it("renders nothing when the server has no AI provider", async () => {
    const fetchMock = serve("not_configured");
    const { container } = render(<AiExplanation scan={makeScan()} />);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("explains what is shared, then shows a labelled explanation on request", async () => {
    serve(
      "active",
      jsonResponse({ explanation: "This link was flagged because…", model: "m", generated_at: "2026-11-16T10:00:00Z", label: "" }),
    );
    render(<AiExplanation scan={makeScan()} />);
    expect(await screen.findByText(/not your message, file or full links/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Explain this result" }));
    expect(await screen.findByText("This link was flagged because…")).toBeInTheDocument();
    expect(screen.getByText(/Written by AI/)).toBeInTheDocument();
  });

  it("shows an existing explanation without asking again", () => {
    const fetchMock = serve("active");
    render(<AiExplanation scan={makeScan({ ai_explanation: "Already explained." })} />);
    expect(screen.getByText("Already explained.")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

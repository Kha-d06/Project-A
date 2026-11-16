import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { router } from "@/test/setup";
import { jsonResponse, makeScan, mockFetch } from "@/test/fixtures";

import { FileScanForm, MAX_FILE_BYTES, MessageScanForm, UrlScanForm } from "./scan-forms";

describe("UrlScanForm", () => {
  it("requires a link before submitting", async () => {
    const fetchMock = mockFetch(jsonResponse(makeScan()));
    render(<UrlScanForm reportBase="/scans" />);
    await userEvent.click(screen.getByRole("button", { name: "Check link" }));
    expect(screen.getByText("Enter a link to check.")).toBeInTheDocument();
    expect(screen.getByLabelText("Link to check")).toHaveAttribute("aria-invalid", "true");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("opens the report once the scan is queued", async () => {
    mockFetch(jsonResponse(makeScan({ status: "queued", risk: null }), 202));
    render(<UrlScanForm reportBase="/scans" />);
    await userEvent.type(screen.getByLabelText("Link to check"), "example.org");
    await userEvent.click(screen.getByRole("button", { name: "Check link" }));
    expect(router.push).toHaveBeenCalledWith(`/scans/${makeScan().id}`);
  });

  it("shows the server's validation message next to the field", async () => {
    mockFetch(
      jsonResponse(
        {
          error: {
            code: "validation_error",
            message: "Only http:// and https:// links can be checked.",
            details: [{ field: "url", message: "Only http:// and https:// links can be checked." }],
          },
        },
        422,
      ),
    );
    render(<UrlScanForm reportBase="/scans" />);
    await userEvent.type(screen.getByLabelText("Link to check"), "javascript:alert(1)");
    await userEvent.click(screen.getByRole("button", { name: "Check link" }));
    expect(await screen.findByText("Only http:// and https:// links can be checked.")).toBeInTheDocument();
  });

  it("explains rate limiting", async () => {
    mockFetch(jsonResponse({ error: { code: "rate_limited", message: "Too many requests. Please wait 30 seconds and try again." } }, 429));
    render(<UrlScanForm reportBase="/scans" />);
    await userEvent.type(screen.getByLabelText("Link to check"), "example.org");
    await userEvent.click(screen.getByRole("button", { name: "Check link" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Please wait 30 seconds");
  });
});

describe("MessageScanForm", () => {
  it("asks for enough text to analyse", async () => {
    render(<MessageScanForm reportBase="/scans" />);
    await userEvent.type(screen.getByLabelText("Message text"), "hi");
    await userEvent.click(screen.getByRole("button", { name: "Analyse message" }));
    expect(screen.getByText(/enough text to analyse/)).toBeInTheDocument();
  });
});

describe("FileScanForm", () => {
  it("rejects files over the size limit before uploading", async () => {
    const fetchMock = mockFetch(jsonResponse(makeScan()));
    render(<FileScanForm reportBase="/scans" />);
    const big = new File(["x"], "big.iso");
    Object.defineProperty(big, "size", { value: MAX_FILE_BYTES + 1 });
    await userEvent.upload(screen.getByLabelText("File to scan"), big);
    expect(screen.getByText(/cannot be scanned/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Scan file" }));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uploads a chosen file", async () => {
    const fetchMock = mockFetch(jsonResponse(makeScan({ scan_type: "file" }), 202));
    render(<FileScanForm reportBase="/scans" />);
    await userEvent.upload(screen.getByLabelText("File to scan"), new File(["hello"], "notes.txt"));
    expect(screen.getByText("notes.txt")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Scan file" }));
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.body).toBeInstanceOf(FormData);
    expect(router.push).toHaveBeenCalled();
  });
});

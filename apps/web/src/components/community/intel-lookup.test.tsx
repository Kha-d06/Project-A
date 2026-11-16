import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { jsonResponse } from "@/test/fixtures";

import { IntelLookup, lookupKind } from "./intel-lookup";

describe("lookupKind", () => {
  it.each([
    ["example.com", "domain"],
    ["https://shop.example.com/path?x=1", "domain"],
    ["203.0.113.7", "ip"],
    ["2001:db8::1", "ip"],
    ["a".repeat(64), "hash"],
    ["not a thing", null],
  ])("classifies %s", (input, kind) => expect(lookupKind(input)).toBe(kind));
});

describe("IntelLookup", () => {
  it("looks up the domain part of a pasted link and states the limits", async () => {
    const fetchMock = vi.fn(async (url: string) =>
      url.includes("/intelligence/domain/")
        ? jsonResponse({
            query: "shop.example.com",
            kind: "domain",
            verdict: "not_listed",
            indicators: [],
            sources: [{ name: "URLhaus (abuse.ch)", indicators: 10, last_updated: "2026-11-16T10:00:00Z", fresh: true }],
            notes: ["Not being listed is not a guarantee."],
          })
        : jsonResponse([]),
    );
    vi.stubGlobal("fetch", fetchMock);
    render(<IntelLookup />);
    await userEvent.type(screen.getByLabelText(/Domain, IP address/), "https://shop.example.com/login");
    await userEvent.click(screen.getByRole("button", { name: /Look up/ }));
    expect(await screen.findByText("Not listed in the sources below")).toBeInTheDocument();
    expect(screen.getByText("Not being listed is not a guarantee.")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => url === "/api/v1/intelligence/domain/shop.example.com")).toBe(true);
  });

  it("explains unsupported input without calling the server", async () => {
    const fetchMock = vi.fn<(url: string) => Promise<Response>>(async () => jsonResponse([]));
    vi.stubGlobal("fetch", fetchMock);
    render(<IntelLookup />);
    await userEvent.type(screen.getByLabelText(/Domain, IP address/), "hello");
    await userEvent.click(screen.getByRole("button", { name: /Look up/ }));
    expect(screen.getByText(/Enter a domain/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.every(([url]) => !String(url).includes("/intelligence/"))).toBe(true);
  });
});

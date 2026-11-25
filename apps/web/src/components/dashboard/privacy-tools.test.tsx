import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ToastProvider } from "@/components/ui/toast";
import { STORAGE_KEY } from "@/lib/brokers";
import { jsonResponse, mockFetch } from "@/test/fixtures";

import { BrokerChecklist, resetBrokerStore } from "./broker-checklist";
import { EmailAliases } from "./email-aliases";

const alias = {
  id: "a1",
  address: "k3x7mq2p9z@relay.example",
  label: "shop",
  paused: false,
  created_at: "2026-11-20T10:00:00Z",
  forwarded_count: 4,
  blocked_count: 1,
  last_forwarded_at: null,
};
const list = (aliases: unknown[], extra: Record<string, unknown> = {}) =>
  jsonResponse({ aliases, domains: ["relay.example"], forwards_to: "me@example.com", ...extra });

const withToasts = (node: React.ReactNode) => render(<ToastProvider>{node}</ToastProvider>);

// jsdom has no modal dialogs.
beforeAll(() => {
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.removeAttribute("open");
  };
});

describe("email aliases", () => {
  it("lists aliases and creates a random one", async () => {
    const fetchMock = mockFetch(list([alias]), jsonResponse({ ...alias, id: "a2", address: "new@relay.example" }, 201), list([alias]));
    withToasts(<EmailAliases />);
    expect(await screen.findByText(alias.address)).toBeInTheDocument();
    expect(screen.getByText(/4 forwarded · 1 refused/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("What it's for (optional)"), "newsletter");
    await userEvent.click(screen.getByRole("button", { name: "New alias" }));
    expect(await screen.findByText("Created new@relay.example")).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(url).toMatch(/\/aliases$/);
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ label: "newsletter" });
  });

  it("pauses and deletes after confirming", async () => {
    const fetchMock = mockFetch(list([alias]), jsonResponse({ ...alias, paused: true }), list([{ ...alias, paused: true }]), jsonResponse(null, 204), list([]));
    withToasts(<EmailAliases />);
    await userEvent.click(await screen.findByRole("button", { name: `Pause: ${alias.address}` }));
    expect(await screen.findByRole("button", { name: `Resume: ${alias.address}` })).toBeInTheDocument();
    expect(JSON.parse(String(fetchMock.mock.calls[1]![1]?.body))).toEqual({ paused: true });
    await userEvent.click(screen.getByRole("button", { name: `Delete: ${alias.address}` }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/refused for good/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("No aliases yet.")).toBeInTheDocument();
    expect(fetchMock.mock.calls[3]![1]?.method).toBe("DELETE");
  });

  it("explains why it can't create one yet", async () => {
    mockFetch(list([], { forwards_to: null }));
    withToasts(<EmailAliases />);
    expect(await screen.findByText(/Verify your email address first/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New alias" })).not.toBeInTheDocument();
  });
});

describe("broker checklist", () => {
  beforeEach(() => {
    window.localStorage.removeItem(STORAGE_KEY);
    resetBrokerStore();
  });

  it("marks progress in this browser only and sends nothing", async () => {
    const fetchMock = mockFetch(jsonResponse({}));
    const now = () => Date.parse("2026-11-25T10:00:00Z");
    withToasts(<BrokerChecklist now={now} />);
    expect(screen.getByText(/^0 of 13 done/)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Spokeo: To do" }), "requested");
    expect(screen.getByText(/^1 of 13 done/)).toBeInTheDocument();
    expect(screen.getByText(/Expected by/)).toBeInTheDocument();
    expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY)!)).toHaveProperty("spokeo.state", "requested");
    expect(fetchMock).not.toHaveBeenCalled();
    const link = screen.getAllByRole("link", { name: /Open opt-out page/ })[0]!;
    expect(link).toHaveAttribute("href", "https://www.spokeo.com/optout");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("flags a re-check after 90 days", async () => {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ spokeo: { state: "removed", at: "2026-08-01T00:00:00Z" } }));
    withToasts(<BrokerChecklist now={() => Date.parse("2026-11-25T10:00:00Z")} />);
    expect(screen.getByText(/1 due for a re-check/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Re-check now" }));
    expect(screen.queryByText(/due for a re-check/)).not.toBeInTheDocument();
  });

  it("makes a request letter without saving the name or email", async () => {
    withToasts(<BrokerChecklist now={() => Date.parse("2026-11-25T10:00:00Z")} />);
    const acxiom = screen.getByText("Acxiom").closest("li")!;
    await userEvent.click(within(acxiom).getByRole("button", { name: "Request letter" }));
    expect(within(acxiom).getByText("Enter your name and a valid email address.")).toBeInTheDocument();
    await userEvent.type(within(acxiom).getByLabelText("Your name"), "Sara Ali");
    await userEvent.type(within(acxiom).getByLabelText("Your email"), "sara@example.com");
    expect((within(acxiom).getByRole("textbox", { name: /Article 17/ }) as HTMLTextAreaElement).value).toContain("Name: Sara Ali");
    expect(window.localStorage.getItem(STORAGE_KEY) ?? "").not.toContain("Sara");
  });
});

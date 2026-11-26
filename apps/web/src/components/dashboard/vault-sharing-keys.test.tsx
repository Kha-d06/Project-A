import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";

import { ToastProvider } from "@/components/ui/toast";
import { type VaultDoc, newItem } from "@/lib/vault";
import { generateSharingKeys, keyFingerprint } from "@/lib/vault-sharing";

import { SharingPanel } from "./password-vault";

/** A server stand-in answering by path, recording what was posted. */
function server(recipientKey: string) {
  const posted: { url: string; body: unknown }[] = [];
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    if (method !== "GET") posted.push({ url, body: init?.body ? JSON.parse(String(init.body)) : null });
    if (url.endsWith("/vault/sharing-key")) return json({ ok: true });
    if (url.endsWith("/vault/recipients")) return json([{ user_id: "u1", email: "sara@example.com", public_key: recipientKey }]);
    if (url.endsWith("/vault/shares")) return method === "POST" ? json({ id: "s1" }, 201) : json([]);
    if (url.endsWith("/vault/emergency")) return json([]);
    return json({ error: { code: "not_found", message: "?" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return posted;
}

async function setup(pinned?: Record<string, string>) {
  const mine = await generateSharingKeys();
  const theirs = await generateSharingKeys();
  const item = newItem("login", { title: "Bank", username: "me", password: "pw", url: "https://bank.example" });
  const doc: VaultDoc = { format: 1, items: [item], sharing: { ...mine, pinned } };
  const persist = vi.fn<(next: VaultDoc) => Promise<boolean>>(async () => true);
  const posted = server(theirs.publicKey);
  render(
    <ToastProvider>
      <SharingPanel doc={doc} persist={persist} />
    </ToastProvider>,
  );
  await userEvent.click(screen.getByText("Sharing and emergency access"));
  await userEvent.selectOptions(await screen.findByLabelText("Login to share"), item.id);
  await waitFor(() => expect(screen.getAllByRole("option", { name: "sara@example.com" }).length).toBeGreaterThan(0));
  return { persist, posted, theirPrint: await keyFingerprint(theirs.publicKey), myPrint: await keyFingerprint(mine.publicKey) };
}

describe("sharing keys are checked on this device", () => {
  it("shows both fingerprints and remembers the recipient's key at first share", async () => {
    const { persist, posted, theirPrint, myPrint } = await setup();
    expect(await screen.findByText(myPrint)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getAllByLabelText("Share with")[0]!, "u1");
    expect(await screen.findByText(theirPrint)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Share" }));
    await waitFor(() => expect(posted.some((p) => p.url.endsWith("/vault/shares"))).toBe(true));
    await waitFor(() => expect(persist).toHaveBeenCalled());
    expect(persist.mock.calls.at(-1)![0].sharing?.pinned).toEqual({ u1: theirPrint });
  });

  it("blocks sharing to a changed key until the person confirms they checked it", async () => {
    const { posted, theirPrint } = await setup({ u1: "0000 0000 0000 0000 0000 0000 0000 0000" });
    await userEvent.selectOptions(screen.getAllByLabelText("Share with")[0]!, "u1");
    expect(await screen.findByRole("alert")).toHaveTextContent(/key has changed/);
    expect(screen.getByText(theirPrint)).toBeInTheDocument();
    const share = screen.getByRole("button", { name: "Share" });
    expect(share).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "I checked it with them" }));
    expect(share).toBeEnabled();
    await userEvent.click(share);
    await waitFor(() => expect(posted.some((p) => p.url.endsWith("/vault/shares"))).toBe(true));
  });
});

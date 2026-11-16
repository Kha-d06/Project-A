import type { AccountLink } from "../lib/api";
import { byId, el } from "../lib/dom";
import { ask, type Status } from "../lib/messages";
import { normalizeHostEntry, type Settings } from "../lib/settings";

const SWITCHES = ["paused", "warnOnSuspicious", "downloadChecks", "keepLocalAlerts", "hoverChecks"] as const;
const HOVER_PERMISSIONS: chrome.permissions.Permissions = {
  permissions: ["scripting"],
  origins: ["http://*/*", "https://*/*"],
};

function flash(message: string) {
  const saved = byId("saved");
  saved.textContent = message;
  window.setTimeout(() => {
    if (saved.textContent === message) saved.textContent = "";
  }, 3000);
}

async function save(changes: Partial<Settings>, message = "Saved.") {
  try {
    await ask<Settings>({ type: "settings", changes });
    flash(message);
  } catch (error) {
    flash(error instanceof Error ? error.message : String(error));
  }
}

function parseList(text: string): { hosts: string[]; rejected: string[] } {
  const hosts = new Set<string>();
  const rejected: string[] = [];
  for (const line of text.split(/\n|,/)) {
    if (!line.trim()) continue;
    const host = normalizeHostEntry(line);
    if (host) hosts.add(host);
    else rejected.push(line.trim());
  }
  return { hosts: [...hosts], rejected };
}

function renderAccount(status: Status) {
  const box = byId("account");
  box.replaceChildren();
  const error = el("p", { class: "faint", role: "alert" });
  const run = async (action: () => Promise<unknown>) => {
    error.textContent = "";
    try {
      await action();
      renderAccount(await ask<Status>({ type: "status" }));
    } catch (caught) {
      error.textContent = caught instanceof Error ? caught.message : String(caught);
    }
  };

  if (status.state === "not_enrolled") {
    box.append(
      el("p", { class: "muted" }, "This extension is not connected to the server yet, so sites are not being checked."),
      el("div", {}, el("button", { type: "button", onclick: () => run(() => ask({ type: "enroll" })) }, "Connect now")),
      error,
    );
    return;
  }
  const account: AccountLink | null = status.account;
  if (account?.linked) {
    box.append(
      el("p", {}, "Linked to ", el("strong", {}, account.account_email ?? "your account"), "."),
      el(
        "p",
        { class: "muted" },
        account.sync_events
          ? "Warnings are recorded in your SENTINEL history (only the domain and the verdict). You can turn this off in your dashboard settings."
          : "Nothing is recorded in your account. You can choose to keep a history of warnings in your dashboard settings.",
      ),
      el("div", {}, el("button", { type: "button", class: "secondary", onclick: () => run(() => ask({ type: "unlink" })) }, "Unlink from account")),
      error,
    );
    return;
  }
  const input = el("input", { type: "text", id: "link-code", placeholder: "ABCD-1234", autocomplete: "off", spellcheck: "false", "aria-label": "Link code" });
  box.append(
    el("p", { class: "muted" }, "Protection works without an account. Linking lets you see this browser in your dashboard and, if you choose, keep a history of warnings."),
    el("p", { class: "muted" }, "In your SENTINEL dashboard, open Browser protection and create a link code, then enter it here."),
    el(
      "div",
      { class: "row" },
      input,
      el(
        "button",
        {
          type: "button",
          onclick: () =>
            run(async () => {
              if (!input.value.trim()) throw new Error("Enter the code shown in your dashboard.");
              await ask({ type: "link", code: input.value });
            }),
        },
        "Link",
      ),
    ),
    error,
  );
}

async function main() {
  // Refresh the account state before rendering, so the form is not replaced while
  // someone is typing a link code into it.
  await ask<AccountLink>({ type: "refresh-account" }).catch(() => undefined);
  const status = await ask<Status>({ type: "status" });
  const { settings } = status;

  for (const key of SWITCHES) {
    const input = byId<HTMLInputElement>(key);
    input.checked = settings[key];
    input.addEventListener("change", async () => {
      if (key === "hoverChecks" && input.checked) {
        // Must be requested from the click handler, as a direct user gesture.
        const granted = await chrome.permissions.request(HOVER_PERMISSIONS);
        if (!granted) {
          input.checked = false;
          flash("Hover checks need permission to run on web pages; nothing was changed.");
          return;
        }
      }
      if (key === "hoverChecks" && !input.checked) await chrome.permissions.remove(HOVER_PERMISSIONS);
      await save({ [key]: input.checked });
    });
  }

  for (const radio of document.querySelectorAll<HTMLInputElement>("input[name=privacyMode]")) {
    radio.checked = radio.value === settings.privacyMode;
    radio.addEventListener("change", () => save({ privacyMode: radio.value as Settings["privacyMode"] }));
  }

  const allow = byId<HTMLTextAreaElement>("allowlist");
  const block = byId<HTMLTextAreaElement>("blocklist");
  allow.value = settings.allowlist.join("\n");
  block.value = settings.blocklist.join("\n");
  byId("save-lists").addEventListener("click", async () => {
    const allowed = parseList(allow.value);
    const blocked = parseList(block.value);
    allow.value = allowed.hosts.join("\n");
    block.value = blocked.hosts.join("\n");
    const rejected = [...allowed.rejected, ...blocked.rejected];
    await save(
      { allowlist: allowed.hosts, blocklist: blocked.hosts },
      rejected.length ? `Saved. Ignored entries that are not domain names: ${rejected.join(", ")}` : "Lists saved.",
    );
  });

  const server = byId<HTMLInputElement>("serverUrl");
  server.value = settings.serverUrl;
  byId("save-server").addEventListener("click", async () => {
    let origin: string;
    try {
      const parsed = new URL(server.value.trim());
      if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
        flash("Use an https:// address, except for a server on this computer.");
        return;
      }
      origin = parsed.origin;
    } catch {
      flash("Enter a full address, such as https://sentinel.example.org");
      return;
    }
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) {
      flash("The extension needs permission to contact that server; nothing was changed.");
      return;
    }
    await save({ serverUrl: origin }, "Server changed. Connecting…");
    try {
      await ask({ type: "enroll" });
      flash("Connected to the new server.");
    } catch (error) {
      flash(`Saved, but the server could not be reached: ${error instanceof Error ? error.message : String(error)}`);
    }
    renderAccount(await ask<Status>({ type: "status" }));
  });

  byId("clear-alerts").addEventListener("click", async () => {
    await ask({ type: "clear-alerts" });
    flash("Alert list cleared.");
  });
  byId("clear-cache").addEventListener("click", async () => {
    await ask({ type: "clear-cache" });
    flash("Cached results cleared.");
  });

  renderAccount(status);
}

void main();

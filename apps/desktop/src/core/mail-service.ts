/**
 * The local email check for any interface over qalaa-ipc (until now only inside
 * the Electron window). Engine unchanged (engine/mail.ts): one IMAP inbox,
 * opened read-only, so nothing is moved, deleted or marked as read. Each new
 * message is checked on this computer (sender, reply address, the provider's
 * authentication results, link text, scam wording). Only its links, cut down to
 * the site and path, go to the Qalaa server for a threat-list lookup. Message
 * bodies never leave the computer.
 *
 * The password (an app password where the provider offers one) is kept in the
 * system keychain (core/keychain.ts). Where there's none, or saving fails, it's
 * kept in memory until the service restarts, and the status says so. It's never
 * written to a plain file or sent anywhere but the mail server.
 */
import { readFile, writeFile } from "node:fs/promises";

import type { MailAccount, MailResult, MailState } from "../engine/mail";
import type { Keychain } from "./keychain";
import { IpcError } from "./protocol";

export const WATCH_MS = 15 * 60 * 1000;
const KEY_NAME = "mail-password";

export interface MailStatus {
  account: MailAccount | null;
  watch: boolean;
  checking: boolean;
  hasPassword: boolean;
  /** The password is in the system keychain (false: in memory until the service restarts). */
  keychain: boolean;
  lastCheck: string | null;
  lastError: string | null;
  results: MailResult[];
}

interface MailConfig {
  account: MailAccount | null;
  watch: boolean;
  state: MailState;
}

export interface MailDeps {
  file: string;
  keychain: Keychain;
  emptyState: MailState;
  sanitizeAccount: (input: Record<string, unknown>) => MailAccount;
  scanInbox: (account: MailAccount, password: string, state: MailState) => Promise<{ state: MailState; added: MailResult[] }>;
  worrying: (results: MailResult[]) => MailResult[];
  emit: (event: "alert", payload: unknown) => void;
}

export class MailService {
  private config: MailConfig;
  private sessionPassword: string | null = null;
  private inKeychain = false;
  private checking: Promise<MailStatus> | null = null;
  private timer: NodeJS.Timeout | null = null;

  constructor(private readonly deps: MailDeps) {
    this.config = { account: null, watch: false, state: { ...deps.emptyState } };
  }

  async load(): Promise<void> {
    try {
      const saved = JSON.parse(await readFile(this.deps.file, "utf8")) as Partial<MailConfig>;
      this.config = { account: saved.account ?? null, watch: saved.watch === true, state: { ...this.deps.emptyState, ...(saved.state ?? {}) } };
    } catch {
      // nothing saved yet
    }
    this.inKeychain = (await this.deps.keychain.get(KEY_NAME).catch(() => null)) !== null;
  }

  private async password(): Promise<string | null> {
    if (this.sessionPassword) return this.sessionPassword;
    return this.deps.keychain.get(KEY_NAME).catch(() => null);
  }

  async status(): Promise<MailStatus> {
    const s = this.config.state;
    return {
      account: this.config.account,
      watch: this.config.watch,
      checking: this.checking !== null,
      hasPassword: (await this.password()) !== null,
      keychain: this.inKeychain,
      lastCheck: s.lastCheck,
      lastError: s.lastError,
      results: s.results,
    };
  }

  /** Saves the account and password, then checks the inbox once. */
  async connect(params: unknown): Promise<MailStatus> {
    const p = (params ?? {}) as Record<string, unknown>;
    const password = typeof p.password === "string" ? p.password : "";
    if (!password) throw new IpcError("bad_params", "Enter the password or app password.");
    if (password.length > 4096 || /[\r\n\0]/.test(password)) throw new IpcError("bad_params", "That password can't be used.");
    let account: MailAccount;
    try {
      account = this.deps.sanitizeAccount(p);
    } catch (error) {
      throw new IpcError("bad_params", error instanceof Error ? error.message : String(error));
    }
    this.sessionPassword = null;
    this.inKeychain = false;
    if (await this.deps.keychain.available().catch(() => false)) {
      try {
        await this.deps.keychain.set(KEY_NAME, password);
        this.inKeychain = true;
      } catch {
        // No keyring running (a headless session, say): keep it for this session only.
      }
    }
    if (!this.inKeychain) this.sessionPassword = password;
    this.config = { account, watch: this.config.watch, state: { ...this.deps.emptyState } };
    await this.save();
    return this.check();
  }

  async disconnect(): Promise<MailStatus> {
    this.sessionPassword = null;
    this.inKeychain = false;
    await this.deps.keychain.remove(KEY_NAME).catch(() => undefined);
    this.config = { account: null, watch: false, state: { ...this.deps.emptyState } };
    await this.save();
    this.applyWatch();
    return this.status();
  }

  /** Checks new mail; concurrent requests share one check. */
  check(): Promise<MailStatus> {
    this.checking ??= this.runCheck().finally(() => {
      this.checking = null;
    });
    return this.checking;
  }

  private async runCheck(): Promise<MailStatus> {
    const password = await this.password();
    if (!this.config.account) throw new IpcError("not_set_up", "Connect an inbox first.");
    if (!password) throw new IpcError("no_password", "Enter the password again: it was kept only until Qalaa's background service restarted.");
    const { state, added } = await this.deps.scanInbox(this.config.account, password, this.config.state);
    this.config = { ...this.config, state };
    await this.save();
    const worrying = this.deps.worrying(added);
    if (worrying.length) this.deps.emit("alert", { kind: "mail", count: worrying.length, subject: worrying[0]?.subject ?? "" });
    // The status reports checking: false, because the check is done.
    this.checking = null;
    return this.status();
  }

  async setWatch(params: unknown): Promise<MailStatus> {
    const on = (params as { on?: unknown } | undefined)?.on;
    if (typeof on !== "boolean") throw new IpcError("bad_params", '"on" must be true or false.');
    if (on && !this.config.account) throw new IpcError("not_set_up", "Connect an inbox first.");
    this.config = { ...this.config, watch: on };
    await this.save();
    this.applyWatch();
    return this.status();
  }

  /** Checks every 15 minutes while watching is on (the daemon calls this at start). */
  applyWatch(): void {
    const want = this.config.watch && this.config.account !== null;
    if (want && !this.timer) {
      this.timer = setInterval(() => void this.check().catch(() => undefined), WATCH_MS);
      this.timer.unref();
    } else if (!want && this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private save(): Promise<void> {
    // Account (host, port, user name) and results only: the password is never in this file.
    return writeFile(this.deps.file, JSON.stringify(this.config), { mode: 0o600 });
  }
}

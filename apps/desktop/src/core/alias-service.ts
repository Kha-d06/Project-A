/**
 * Disposable email aliases from the desktop: the linked account asks the
 * Qalaa server for a new address; optionally it is put on the clipboard
 * (plainly: an alias isn't a secret, so it isn't auto-cleared).
 */
import { AccountLinkError, type EmailAlias, type LinkedAccount, createAlias, listAliases } from "../engine/account";
import { IpcError } from "./protocol";

export class AliasService {
  constructor(
    private readonly account: () => Promise<LinkedAccount | null>,
    private readonly copy: ((text: string) => Promise<void>) | null,
    private readonly api = { createAlias, listAliases },
  ) {}

  private async linked(): Promise<LinkedAccount> {
    const account = await this.account();
    if (!account) throw new IpcError("not_linked", "Link this computer to your Qalaa account first (Settings, Account).");
    return account;
  }

  async list() {
    return this.wrap(async () => this.api.listAliases(await this.linked()));
  }

  async create(params: unknown): Promise<EmailAlias & { copied: boolean }> {
    const { label, copy } = (params ?? {}) as { label?: unknown; copy?: unknown };
    if (label !== undefined && (typeof label !== "string" || label.length > 120)) throw new IpcError("bad_params", "The label is too long.");
    const alias = await this.wrap(async () => this.api.createAlias(await this.linked(), (label as string | undefined) ?? null));
    let copied = false;
    if (copy === true && this.copy) {
      await this.copy(alias.address).then(() => (copied = true)).catch(() => undefined);
    }
    return { ...alias, copied };
  }

  private async wrap<T>(task: () => Promise<T>): Promise<T> {
    try {
      return await task();
    } catch (error) {
      if (error instanceof IpcError) throw error;
      if (error instanceof AccountLinkError) throw new IpcError(error.status === 409 ? "unavailable" : "server_error", error.message);
      throw new IpcError("server_error", "The Qalaa server couldn't be reached.");
    }
  }
}

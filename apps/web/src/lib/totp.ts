/**
 * Time-based one-time passwords (RFC 6238) for vault entries.
 *
 * Everything runs in the browser with Web Crypto; the secret is stored only
 * inside the end-to-end-encrypted vault, never sent anywhere. Supports the
 * otpauth:// URI that authenticator QR codes encode, and a bare base32 secret.
 */

/** Decode RFC 4648 base32 (no padding needed), ignoring spaces and case. */
export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.replace(/[\s=]/g, "").toUpperCase();
  if (!clean) return new Uint8Array(0);
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index === -1) throw new Error("not valid base32");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

export interface TotpConfig {
  secret: string; // base32
  algorithm: "SHA-1" | "SHA-256" | "SHA-512";
  digits: number;
  period: number;
  issuer: string | null;
  account: string | null;
}

const DEFAULTS = { algorithm: "SHA-1" as const, digits: 6, period: 30 };

/**
 * Parse an otpauth://totp/... URI or a bare base32 secret into a config.
 * Returns null if it is not a usable TOTP source.
 */
export function parseOtpauth(input: string): TotpConfig | null {
  const text = input.trim();
  if (!text) return null;
  if (!/^otpauth:\/\//i.test(text)) {
    // Treat the whole thing as a bare base32 secret.
    try {
      if (base32Decode(text).length === 0) return null;
    } catch {
      return null;
    }
    return { secret: text.replace(/\s/g, ""), ...DEFAULTS, issuer: null, account: null };
  }
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.host.toLowerCase() !== "totp") return null; // HOTP not supported here
  const params = url.searchParams;
  const secret = params.get("secret");
  if (!secret) return null;
  try {
    if (base32Decode(secret).length === 0) return null;
  } catch {
    return null;
  }
  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [labelIssuer, labelAccount] = label.includes(":") ? label.split(":", 2) : [null, label];
  const algoRaw = (params.get("algorithm") ?? "SHA1").toUpperCase();
  const algorithm = algoRaw === "SHA256" ? "SHA-256" : algoRaw === "SHA512" ? "SHA-512" : "SHA-1";
  const digits = Math.min(10, Math.max(6, Number(params.get("digits")) || 6));
  const period = Math.min(120, Math.max(10, Number(params.get("period")) || 30));
  return {
    secret: secret.replace(/\s/g, ""),
    algorithm,
    digits,
    period,
    issuer: params.get("issuer") ?? labelIssuer ?? null,
    account: labelAccount ?? null,
  };
}

/** Compute the TOTP code for a given config at a given time (ms since epoch). */
export async function totpCode(config: TotpConfig, atMs: number = Date.now()): Promise<string> {
  const counter = Math.floor(atMs / 1000 / config.period);
  const key = base32Decode(config.secret);
  // 8-byte big-endian counter.
  const message = new Uint8Array(8);
  let value = counter;
  for (let i = 7; i >= 0; i--) {
    message[i] = value & 0xff;
    value = Math.floor(value / 256);
  }
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: config.algorithm }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, message));
  // Dynamic truncation (RFC 4226 §5.3).
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binary =
    ((hmac[offset]! & 0x7f) << 24) | ((hmac[offset + 1]! & 0xff) << 16) | ((hmac[offset + 2]! & 0xff) << 8) | (hmac[offset + 3]! & 0xff);
  return (binary % 10 ** config.digits).toString().padStart(config.digits, "0");
}

/** Seconds remaining in the current step, for a countdown ring. */
export function secondsRemaining(config: TotpConfig, atMs: number = Date.now()): number {
  return config.period - (Math.floor(atMs / 1000) % config.period);
}

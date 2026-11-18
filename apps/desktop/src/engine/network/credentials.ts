/**
 * The default-password check. This is OFF by default and, when on, the person
 * confirms each device individually. It exists to answer one question: "does
 * this device still have its factory login?" — so they can change it.
 *
 * Hard limits, enforced here:
 *  - at most MAX_TRIES logins per device,
 *  - private addresses only,
 *  - stop at the first sign of a lockout,
 *  - nothing is ever stored or sent anywhere; the result is a yes/no and advice.
 */
import { Socket } from "node:net";

import { classifyIp } from "../nettools";
import { DEFAULT_LOGINS } from "./vendors";

export const MAX_TRIES = 5;

export interface CredentialResult {
  device: string;
  /** "http" | "telnet" | "ftp" — which service was checked. */
  service: string;
  /** True when a factory default login was accepted. */
  defaultAccepted: boolean;
  /** The user name that worked, so the person knows which to change. Never the password alone from an input. */
  user: string | null;
  /** How many logins were tried before stopping. */
  tried: number;
  /** Set when the check stopped early (lockout, unreachable). */
  stopped: string | null;
}

/** Try HTTP Basic auth against a device's admin page with the factory logins. */
export async function checkHttp(ip: string, port = 80, fetchImpl: typeof fetch = fetch): Promise<CredentialResult> {
  const result: CredentialResult = { device: ip, service: "http", defaultAccepted: false, user: null, tried: 0, stopped: null };
  if (classifyIp(ip) !== "private" && classifyIp(ip) !== "link-local") {
    result.stopped = "not a private address";
    return result;
  }
  for (const { user, pass } of DEFAULT_LOGINS.slice(0, MAX_TRIES)) {
    result.tried++;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      const response = await fetchImpl(`http://${ip}:${port}/`, {
        headers: { authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}` },
        signal: controller.signal,
        redirect: "manual",
      });
      clearTimeout(timer);
      // 401/403 => rejected. 429 => being rate-limited, stop. 2xx/3xx => accepted.
      if (response.status === 429 || response.status === 503) {
        result.stopped = "device started refusing attempts";
        break;
      }
      if (response.status < 400) {
        result.defaultAccepted = true;
        result.user = user || "(blank)";
        break;
      }
    } catch {
      result.stopped = "device unreachable";
      break;
    }
  }
  return result;
}

/** A line-based login probe for Telnet/FTP: read the prompt, send a default, look for success. */
export function checkLineService(ip: string, port: number, service: "telnet" | "ftp", timeoutMs = 3000): Promise<CredentialResult> {
  const result: CredentialResult = { device: ip, service, defaultAccepted: false, user: null, tried: 0, stopped: null };
  return new Promise((resolve) => {
    if (classifyIp(ip) !== "private" && classifyIp(ip) !== "link-local") {
      result.stopped = "not a private address";
      resolve(result);
      return;
    }
    const socket = new Socket();
    const logins = DEFAULT_LOGINS.slice(0, MAX_TRIES);
    let index = -1;
    let buffer = "";
    let stage: "user" | "pass" = "user";
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const sendNext = () => {
      index++;
      if (index >= logins.length) {
        finish();
        return;
      }
      result.tried = index + 1;
      stage = "user";
      buffer = "";
      if (service === "ftp") socket.write(`USER ${logins[index]!.user || "anonymous"}\r\n`);
      else socket.write(`${logins[index]!.user}\r\n`);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      if (service === "ftp") return; // wait for the 220 banner before sending USER
      sendNext();
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString("latin1").toLowerCase();
      if (service === "ftp" && index < 0) { sendNext(); return; }
      if (service === "ftp") {
        if (/^331/m.test(buffer)) { socket.write(`PASS ${logins[index]!.pass}\r\n`); buffer = ""; return; }
        if (/^230/m.test(buffer)) { result.defaultAccepted = true; result.user = logins[index]!.user || "anonymous"; finish(); return; }
        if (/^(530|421)/m.test(buffer)) { if (/^421/m.test(buffer)) { result.stopped = "device closed the connection"; finish(); return; } sendNext(); return; }
        return;
      }
      // Telnet: a password prompt, then a shell prompt means success.
      if (stage === "user" && /pass(word)?:/.test(buffer)) { stage = "pass"; buffer = ""; socket.write(`${logins[index]!.pass}\r\n`); return; }
      if (stage === "pass") {
        if (/[#$>]\s*$/.test(buffer)) { result.defaultAccepted = true; result.user = logins[index]!.user || "(blank)"; finish(); return; }
        if (/incorrect|fail|denied|login:/.test(buffer)) { sendNext(); return; }
      }
    });
    socket.once("timeout", () => { result.stopped = result.stopped ?? "no response"; finish(); });
    socket.once("error", () => { result.stopped = "device unreachable"; finish(); });
    try { socket.connect(port, ip); } catch { result.stopped = "device unreachable"; finish(); }
  });
}

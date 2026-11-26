/**
 * Filling saved logins from the Qalaa password vault.
 *
 * Safety rules, enforced in the background script before anything is filled:
 * - only when the person clicks Fill in the popup (never automatically on page
 *   load, which is how hidden-form attacks harvest saved passwords);
 * - only into the top-level page, never an iframe;
 * - only on https:// pages (or a local development server);
 * - only logins saved for this site (same host, or a subdomain of it);
 * - never on a page Qalaa flags as dangerous or that you or your family blocked.
 */
import { parse as parseDomain } from "tldts";

import type { VaultItem } from "../../../web/src/lib/vault";
import type { Verdict } from "./types";

export type FillRefusal = "not_https" | "dangerous_site" | "no_match" | "locked";

export function pageHost(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    return parsed.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return null;
  }
}

export function canFillOn(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === "https:") return true;
    return parsed.protocol === "http:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1");
  } catch {
    return false;
  }
}

/** The saved site matches the page when hosts are equal or the page is a subdomain of it. */
export function savedHost(item: VaultItem): string | null {
  if (!item.url) return null;
  return pageHost(item.url.includes("://") ? item.url : `https://${item.url}`);
}

/** True for "co.uk", "github.io" and the like (ICANN and private suffixes). */
export function isPublicSuffix(host: string): boolean {
  const parsed = parseDomain(host, { allowPrivateDomains: true });
  return parsed.isIp !== true && (parsed.domain === null || parsed.publicSuffix === host);
}

export function loginsFor(items: VaultItem[], pageUrl: string): VaultItem[] {
  const host = pageHost(pageUrl);
  if (!host) return [];
  return items
    .filter((item) => item.kind === "login" && item.password)
    .filter((item) => {
      const saved = savedHost(item);
      if (saved === null) return false;
      if (host === saved) return true;
      // Subdomains match only below a real site: a login saved for a shared
      // suffix ("github.io", "herokuapp.com", "co.uk") would otherwise be offered
      // on every site anyone hosts under it.
      return host.endsWith(`.${saved}`) && !isPublicSuffix(saved);
    })
    .sort((a, b) => Number(savedHost(b) === host) - Number(savedHost(a) === host) || a.title.localeCompare(b.title));
}

const UNSAFE: ReadonlySet<Verdict> = new Set(["dangerous", "suspicious", "blocked_by_you", "blocked_by_family"]);

export function refusal(pageUrl: string, verdict: Verdict | null, matches: number): FillRefusal | null {
  if (!canFillOn(pageUrl)) return "not_https";
  if (verdict && UNSAFE.has(verdict)) return "dangerous_site";
  if (matches === 0) return "no_match";
  return null;
}

/**
 * Runs inside the page (chrome.scripting.executeScript serialises it, so it must
 * not use anything from outside its own body). Fills the first visible password
 * field and the closest visible username/email field before it.
 */
export function fillLoginForm(username: string, password: string, expectedOrigin: string): { filled: boolean; usernameFilled: boolean } {
  // Checked again inside the page, at the moment of filling: the tab may have
  // navigated somewhere else after the background script looked at its address.
  if (location.origin !== expectedOrigin || window.top !== window) return { filled: false, usernameFilled: false };
  const visible = (field: HTMLInputElement) => {
    const box = field.getBoundingClientRect();
    const style = getComputedStyle(field);
    return box.width > 1 && box.height > 1 && style.visibility !== "hidden" && style.display !== "none" && !field.disabled && !field.readOnly;
  };
  const setValue = (field: HTMLInputElement, value: string) => {
    // Use the native setter so frameworks (React, Vue) notice the change.
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter ? setter.call(field, value) : (field.value = value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
  const passwordField = inputs.find((field) => field.type === "password" && visible(field));
  if (!passwordField) return { filled: false, usernameFilled: false };
  const before = inputs.slice(0, inputs.indexOf(passwordField)).reverse();
  const userField = before.find(
    (field) =>
      visible(field) &&
      (field.type === "email" ||
        field.type === "text" ||
        field.type === "tel" ||
        /user|email|login|name/i.test(`${field.name} ${field.id} ${field.autocomplete}`)),
  );
  if (userField && username) setValue(userField, username);
  setValue(passwordField, password);
  passwordField.focus();
  return { filled: true, usernameFilled: Boolean(userField && username) };
}

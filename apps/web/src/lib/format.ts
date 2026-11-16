import { type Locale, intlLocale } from "./i18n/locales";

let dateTime = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });
let shortDate = new Intl.DateTimeFormat("en", { month: "short", day: "numeric" });
let relative = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
let currentLocale: Locale = "en";

/** Called by the i18n provider so every formatter follows the page language. */
export function setFormatLocale(locale: Locale) {
  if (locale === currentLocale) return;
  currentLocale = locale;
  const tag = intlLocale(locale);
  dateTime = new Intl.DateTimeFormat(tag, { dateStyle: "medium", timeStyle: "short" });
  shortDate = new Intl.DateTimeFormat(tag, { month: "short", day: "numeric" });
  relative = new Intl.RelativeTimeFormat(tag, { numeric: "auto" });
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

export function formatDateTime(iso: string): string {
  return dateTime.format(new Date(iso));
}

export function formatShortDate(iso: string): string {
  return shortDate.format(new Date(iso));
}

export function formatRelative(iso: string, now: Date = new Date()): string {
  const seconds = (new Date(iso).getTime() - now.getTime()) / 1000;
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit);
  }
  return relative.format(0, "second");
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDuration(startIso: string, endIso: string): string {
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  const seconds = Math.max(ms, 1000) / 1000;
  return new Intl.NumberFormat(intlLocale(currentLocale), { style: "unit", unit: "second", maximumFractionDigits: 1 }).format(seconds);
}

export const LOCALES = ["en", "ar"] as const;
export type Locale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: Locale = "en";
export const LOCALE_COOKIE = "sentinel-locale";

export const LOCALE_NAMES: Record<Locale, string> = { en: "English", ar: "العربية" };

export function isLocale(value: string | null | undefined): value is Locale {
  return LOCALES.includes(value as Locale);
}

export function directionOf(locale: Locale): "ltr" | "rtl" {
  return locale === "ar" ? "rtl" : "ltr";
}

/** Intl locale: Arabic with Latin digits, so codes, hashes and counts read consistently. */
export function intlLocale(locale: Locale): string {
  return locale === "ar" ? "ar-u-nu-latn" : "en";
}

/** Picks a locale from an Accept-Language header when no choice has been saved. */
export function negotiate(acceptLanguage: string | null): Locale {
  const preferred = (acceptLanguage ?? "")
    .split(",")
    .map((part) => part.trim().split(";")[0]?.toLowerCase() ?? "")
    .find((tag) => LOCALES.some((locale) => tag === locale || tag.startsWith(`${locale}-`)));
  return preferred?.startsWith("ar") ? "ar" : DEFAULT_LOCALE;
}

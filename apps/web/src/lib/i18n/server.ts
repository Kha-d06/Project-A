import { cookies, headers } from "next/headers";

import { ar } from "./ar";
import { en } from "./en";
import { type Locale, LOCALE_COOKIE, isLocale, negotiate } from "./locales";

export async function getLocale(): Promise<Locale> {
  // An explicit ?lang= (set by the proxy) wins, so each language has its own URL.
  const explicit = (await headers()).get("x-qalaa-lang");
  if (isLocale(explicit)) return explicit;
  const saved = (await cookies()).get(LOCALE_COOKIE)?.value;
  if (isLocale(saved)) return saved;
  return negotiate((await headers()).get("accept-language"));
}

export function getDictionary(locale: Locale) {
  return locale === "ar" ? ar : en;
}

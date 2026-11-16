"use client";

import { createContext, useContext, type ReactNode } from "react";

import { setRequestLocale } from "@/lib/api/client";
import { setFormatLocale } from "@/lib/format";

import { ar } from "./ar";
import { type Dictionary, en } from "./en";
import { type Locale } from "./locales";

interface I18nValue {
  locale: Locale;
  t: Dictionary;
}

const I18nContext = createContext<I18nValue>({ locale: "en", t: en });

export function I18nProvider({ locale, children }: { locale: Locale; children: ReactNode }) {
  // Formatting and API requests follow the page language. Set during render so the
  // very first render already uses it.
  setFormatLocale(locale);
  setRequestLocale(locale);
  return <I18nContext.Provider value={{ locale, t: locale === "ar" ? ar : en }}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  return useContext(I18nContext);
}

/** Fills {name} placeholders in a translated string. */
export function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (match, key: string) => (key in values ? String(values[key]) : match));
}

"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";

import { cn } from "@/lib/cn";
import { useI18n } from "@/lib/i18n/client";
import {
  applyThemePreference,
  readThemePreference,
  subscribeToTheme,
  type ThemePreference,
} from "@/lib/theme";

const OPTIONS: { value: ThemePreference; key: "light" | "dark" | "system"; icon: typeof Sun }[] = [
  { value: "light", key: "light", icon: Sun },
  { value: "dark", key: "dark", icon: Moon },
  { value: "system", key: "system", icon: Monitor },
];

export function ThemeToggle({ className }: { className?: string }) {
  // The server cannot know the stored choice, so nothing is selected until hydration.
  const preference = useSyncExternalStore(subscribeToTheme, readThemePreference, () => null);
  const { t } = useI18n();

  return (
    <div
      role="radiogroup"
      aria-label={t.theme.group}
      className={cn("inline-flex rounded-control border border-line p-0.5", className)}
    >
      {OPTIONS.map(({ value, key, icon: Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={preference === value}
          aria-label={t.theme[key]}
          title={t.theme[key]}
          onClick={() => applyThemePreference(value)}
          className={cn(
            "grid size-7 place-items-center rounded-[0.35rem] transition-colors",
            preference === value ? "bg-surface-sunken text-ink" : "text-ink-faint hover:text-ink",
          )}
        >
          <Icon aria-hidden className="size-3.5" />
        </button>
      ))}
    </div>
  );
}

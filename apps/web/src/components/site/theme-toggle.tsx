"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";

import { cn } from "@/lib/cn";
import {
  applyThemePreference,
  readThemePreference,
  subscribeToTheme,
  type ThemePreference,
} from "@/lib/theme";

const OPTIONS: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "Light theme", icon: Sun },
  { value: "dark", label: "Dark theme", icon: Moon },
  { value: "system", label: "Match system theme", icon: Monitor },
];

export function ThemeToggle({ className }: { className?: string }) {
  // The server cannot know the stored choice, so nothing is selected until hydration.
  const preference = useSyncExternalStore(subscribeToTheme, readThemePreference, () => null);

  return (
    <div
      role="radiogroup"
      aria-label="Colour theme"
      className={cn("inline-flex rounded-control border border-line p-0.5", className)}
    >
      {OPTIONS.map(({ value, label, icon: Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={preference === value}
          aria-label={label}
          title={label}
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

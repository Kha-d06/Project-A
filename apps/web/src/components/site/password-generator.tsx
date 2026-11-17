"use client";

import { Copy, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { useToast } from "@/components/ui/toast";
import { useI18n } from "@/lib/i18n/client";
import { generatePassphrase, generatePassword, passphraseBits, passwordBits } from "@/lib/password";

export function PasswordGenerator() {
  const { t } = useI18n();
  const p = t.extra.password;
  const notify = useToast();
  const [mode, setMode] = useState<"passphrase" | "password">("passphrase");
  const [words, setWords] = useState(6);
  const [length, setLength] = useState(18);
  const [upper, setUpper] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [seed, setSeed] = useState(0);

  const options = { length, upper, digits, symbols };
  const bits = mode === "passphrase" ? passphraseBits(words) : passwordBits(options);
  // A new value whenever an option changes or "Generate another" is pressed.
  const value = useMemo(
    () => (mode === "passphrase" ? generatePassphrase(words) : generatePassword({ length, upper, digits, symbols })),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- seed only forces a new value
    [mode, words, length, upper, digits, symbols, seed],
  );
  const regenerate = () => setSeed((current) => current + 1);

  return (
    <div className="mx-auto max-w-2xl space-y-6 px-4 py-12 sm:px-6">
      <header className="space-y-2">
        <h1 className="font-display text-display font-bold text-ink">{p.title}</h1>
        <p className="text-lg text-ink-muted">{p.description}</p>
      </header>
      <Panel className="space-y-5 p-5">
        <div className="flex gap-1 rounded-control border border-line p-1" role="group">
          {(["passphrase", "password"] as const).map((item) => (
            <button
              key={item}
              type="button"
              aria-pressed={mode === item}
              onClick={() => setMode(item)}
              className="flex-1 rounded-control px-3 py-2 text-sm text-ink-muted aria-pressed:bg-surface-sunken aria-pressed:font-semibold aria-pressed:text-ink"
            >
              {p[item]}
            </button>
          ))}
        </div>
        <output aria-live="polite" suppressHydrationWarning className="block rounded-control bg-surface-sunken p-4 font-mono text-lg break-all text-ink" dir="ltr">
          {value}
        </output>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm">
            <span className={bits >= 45 ? "font-semibold text-clear" : "font-semibold text-danger"}>{p.verdict(bits)}</span>
            <span className="text-ink-muted"> · {p.strength(bits)}</span>
          </p>
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={regenerate}>
              <RefreshCw aria-hidden className="size-4" />
              {p.generate}
            </Button>
            <Button size="sm" onClick={() => navigator.clipboard.writeText(value).then(() => notify("success", p.copied))}>
              <Copy aria-hidden className="size-4" />
              {p.copy}
            </Button>
          </div>
        </div>
        {mode === "passphrase" ? (
          <label className="block space-y-1 text-sm text-ink">
            <span>
              {p.words}: {words}
            </span>
            <input type="range" min={5} max={10} value={words} onChange={(event) => setWords(Number(event.target.value))} className="w-full accent-[var(--accent)]" />
          </label>
        ) : (
          <div className="space-y-3">
            <label className="block space-y-1 text-sm text-ink">
              <span>
                {p.length}: {length}
              </span>
              <input type="range" min={12} max={64} value={length} onChange={(event) => setLength(Number(event.target.value))} className="w-full accent-[var(--accent)]" />
            </label>
            <div className="flex flex-wrap gap-4 text-sm">
              {(
                [
                  ["upper", upper, setUpper],
                  ["digits", digits, setDigits],
                  ["symbols", symbols, setSymbols],
                ] as const
              ).map(([key, checked, set]) => (
                <label key={key} className="flex items-center gap-2">
                  <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={checked} onChange={(event) => set(event.target.checked)} />
                  {p[key]}
                </label>
              ))}
            </div>
          </div>
        )}
      </Panel>
      <p className="text-sm text-ink-muted">{p.tips}</p>
      <Link href="/dashboard/breach" className="text-sm text-accent underline underline-offset-4">
        {p.check} →
      </Link>
    </div>
  );
}

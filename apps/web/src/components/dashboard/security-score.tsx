"use client";

import { Check, Circle } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api/client";
import type { SecurityScore } from "@/lib/api/types";
import { useI18n } from "@/lib/i18n/client";

const GRADE_TONE: Record<SecurityScore["grade"], string> = {
  strong: "text-clear",
  good: "text-clear",
  fair: "text-warning",
  weak: "text-danger",
};

const STEP_LINK: Record<string, string> = {
  email_verified: "/dashboard/settings",
  two_factor: "/dashboard/settings",
  password_manager: "/dashboard/passwords",
  extension: "/dashboard/browser-protection",
  device_protected: "/dashboard/devices",
  breach_monitoring: "/dashboard/breach",
  vpn: "/dashboard/vpn",
};

/** The account's security score: protective settings only, never a promise of safety. */
export function SecurityScoreCard() {
  const s = useI18n().t.extra.score;
  const [score, setScore] = useState<SecurityScore | null>(null);

  useEffect(() => {
    api.user
      .securityScore()
      .then(setScore)
      .catch(() => undefined);
  }, []);

  if (!score) return null;
  const open = score.steps.filter((step) => !step.done);
  return (
    <Panel>
      <PanelHeader title={s.title} description={s.description} />
      <div className="grid gap-5 p-5 md:grid-cols-[auto_1fr] md:items-center">
        <div className="flex items-center gap-4" id="security-score">
          <div
            className="relative grid size-24 place-items-center rounded-full"
            style={{ background: `conic-gradient(var(--accent) ${score.score * 3.6}deg, var(--surface-sunken) 0deg)` }}
            role="img"
            aria-label={s.label(score.score)}
          >
            <span className="grid size-20 place-items-center rounded-full bg-surface text-2xl font-semibold text-ink">{score.score}</span>
          </div>
          <div>
            <p className={`text-lg font-semibold ${GRADE_TONE[score.grade]}`}>{s.grades[score.grade]}</p>
            <p className="text-sm text-ink-muted">{open.length ? s.stepsLeft(open.length) : s.allDone}</p>
          </div>
        </div>
        <ul className="space-y-2 text-sm">
          {score.steps.map((step) => (
            <li key={step.key} className="flex items-start gap-2">
              {step.done ? (
                <Check aria-hidden className="mt-0.5 size-4 shrink-0 text-clear" />
              ) : (
                <Circle aria-hidden className="mt-0.5 size-4 shrink-0 text-ink-faint" />
              )}
              <span className={step.done ? "text-ink-muted" : "text-ink"}>
                {step.done ? (
                  s.steps[step.key] ?? step.key
                ) : (
                  <Link href={STEP_LINK[step.key] ?? "/dashboard"} className="hover:underline">
                    {s.steps[step.key] ?? step.key}
                  </Link>
                )}
                {!step.done && <span className="text-ink-faint"> · +{step.points}</span>}
              </span>
            </li>
          ))}
        </ul>
      </div>
      <p className="px-5 pb-4 text-xs text-ink-faint">{s.note}</p>
    </Panel>
  );
}

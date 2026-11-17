"use client";

import { Sparkles } from "lucide-react";
import { useEffect, useState } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { ApiError, api } from "@/lib/api/client";
import type { Scan } from "@/lib/api/types";
import { useI18n } from "@/lib/i18n/client";

/**
 * Optional, on-request explanation. Shown only when the server has an AI provider
 * configured, so there is never a button that cannot work.
 */
export function AiExplanation({ scan }: { scan: Scan }) {
  const { t } = useI18n();
  const [available, setAvailable] = useState<boolean | null>(scan.ai_explanation ? true : null);
  const [text, setText] = useState(scan.ai_explanation);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (scan.ai_explanation) return;
    let cancelled = false;
    api.system.providers().then(
      (providers) => !cancelled && setAvailable((Array.isArray(providers) ? providers : []).some((p) => p.key === "ai" && p.status === "active")),
      () => !cancelled && setAvailable(false),
    );
    return () => {
      cancelled = true;
    };
  }, [scan.ai_explanation]);

  if (!available) return null;

  const request = async () => {
    setPending(true);
    setError(null);
    try {
      setText((await api.scans.explain(scan.id)).explanation);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : t.ai.failed);
    } finally {
      setPending(false);
    }
  };

  return (
    <Panel>
      <PanelHeader
        title={t.ai.title}
        description={text ? t.ai.label : t.ai.before}
      />
      <div className="space-y-3 px-5 py-4">
        {text ? (
          <p className="flex animate-fade-up gap-3 text-sm leading-relaxed text-ink">
            <Sparkles aria-hidden className="mt-0.5 size-4 shrink-0 text-accent" />
            <span className="whitespace-pre-line" dir="auto">{text}</span>
          </p>
        ) : (
          <Button variant="secondary" size="sm" pending={pending} onClick={request}>
            <Sparkles aria-hidden className="size-4" />
            {t.ai.button}
          </Button>
        )}
        {error && <Alert tone="warning">{error}</Alert>}
      </div>
    </Panel>
  );
}

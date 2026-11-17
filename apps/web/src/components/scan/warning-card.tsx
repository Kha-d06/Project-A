"use client";

import { Download, Share2 } from "lucide-react";
import { useEffect, useRef } from "react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import type { Scan } from "@/lib/api/types";
import { formatShortDate } from "@/lib/format";
import { useI18n } from "@/lib/i18n/client";
import { drawWarningCard } from "@/lib/warning-card";

export function WarningCardDialog({ scan, open, onClose }: { scan: Scan; open: boolean; onClose: () => void }) {
  const { t, locale } = useI18n();
  const c = t.extra.cards;
  const canvas = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!open || !canvas.current || !scan.risk) return;
    const reason = scan.findings.find((f) => ["critical", "high", "medium"].includes(f.severity))?.title ?? scan.summary ?? "";
    drawWarningCard(canvas.current, scan, {
      heading: c.heading,
      type: t.scanTypes[scan.scan_type],
      verdict: t.risk[scan.risk].label,
      reason,
      doNot: c.doNot,
      footer: `${c.checked} · ${formatShortDate(scan.completed_at ?? scan.created_at)}`,
      rtl: locale === "ar",
    });
  }, [open, scan, c, t, locale]);

  const blob = () => new Promise<Blob | null>((resolve) => canvas.current?.toBlob(resolve, "image/png"));

  const download = async () => {
    const image = await blob();
    if (!image) return;
    const link = document.createElement("a");
    link.href = URL.createObjectURL(image);
    link.download = "sentinel-warning.png";
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const share = async () => {
    const image = await blob();
    if (!image) return;
    const file = new File([image], "sentinel-warning.png", { type: "image/png" });
    if (navigator.canShare?.({ files: [file] })) await navigator.share({ files: [file], title: c.heading }).catch(() => undefined);
    else await download();
  };

  return (
    <Dialog open={open} onClose={onClose} title={c.title} description={c.description}>
      <div className="space-y-4">
        <canvas ref={canvas} className="aspect-square w-full rounded-control border border-line" role="img" aria-label={c.heading} />
        <div className="flex flex-wrap gap-2">
          <Button onClick={share}>
            <Share2 aria-hidden className="size-4" />
            {c.share}
          </Button>
          <Button variant="secondary" onClick={download}>
            <Download aria-hidden className="size-4" />
            {c.download}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            {t.extra.share.close}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

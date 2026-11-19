/** Draws a shareable warning image for a risky result, entirely in the browser. */
import type { Scan } from "@/lib/api/types";

export interface CardText {
  heading: string;
  type: string;
  verdict: string;
  reason: string;
  doNot: string;
  footer: string;
  rtl: boolean;
}

/** Makes a link impossible to tap when posted in a chat: hxxps://evil[.]example/… */
export function defang(target: string): string {
  return target.replace(/^http/i, "hxxp").replace(/\./g, "[.]").slice(0, 90);
}

function wrap(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (ctx.measureText(candidate).width > maxWidth && line) {
      lines.push(line);
      line = word;
    } else {
      line = candidate;
    }
  }
  if (line) lines.push(line);
  return lines.slice(0, 5);
}

export function drawWarningCard(canvas: HTMLCanvasElement, scan: Scan, text: CardText): void {
  const size = 1080;
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const danger = scan.risk === "known_malicious";
  const gradient = ctx.createLinearGradient(0, 0, size, size);
  gradient.addColorStop(0, danger ? "#7a1410" : "#7a4504");
  gradient.addColorStop(1, danger ? "#2b0705" : "#2c1a03");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, size, size);

  ctx.direction = text.rtl ? "rtl" : "ltr";
  ctx.textAlign = text.rtl ? "right" : "left";
  const x = text.rtl ? size - 90 : 90;
  const width = size - 180;
  const font = (weight: number, px: number) => `${weight} ${px}px system-ui, "Segoe UI", "IBM Plex Sans Arabic", sans-serif`;

  ctx.fillStyle = "#ffd7cf";
  ctx.font = font(800, 42);
  ctx.fillText(`⚠ ${text.heading}`, x, 150);

  ctx.fillStyle = "#ffffff";
  ctx.font = font(800, 76);
  ctx.fillText(text.verdict, x, 270);

  ctx.font = font(500, 36);
  ctx.fillStyle = "#ffe9e4";
  ctx.fillText(text.type, x, 340);

  let y = 450;
  // Only addresses are shown (broken so they cannot be tapped); message text and
  // file names stay private.
  if (scan.target && (scan.scan_type === "url" || scan.scan_type === "website")) {
    ctx.save();
    ctx.direction = "ltr";
    ctx.textAlign = text.rtl ? "right" : "left";
    ctx.fillStyle = "rgba(255,255,255,0.12)";
    ctx.fillRect(70, y - 60, size - 140, 90);
    ctx.fillStyle = "#ffffff";
    ctx.font = `500 34px ui-monospace, Menlo, Consolas, monospace`;
    ctx.fillText(defang(scan.target), x, y);
    ctx.restore();
    y += 110;
  }

  ctx.fillStyle = "#ffffff";
  ctx.font = font(600, 40);
  for (const line of wrap(ctx, text.reason, width)) {
    ctx.fillText(line, x, y);
    y += 56;
  }
  y += 30;
  ctx.font = font(500, 36);
  ctx.fillStyle = "#ffe9e4";
  for (const line of wrap(ctx, text.doNot, width)) {
    ctx.fillText(line, x, y);
    y += 50;
  }

  ctx.fillStyle = "rgba(255,255,255,0.75)";
  ctx.font = font(500, 30);
  ctx.fillText(text.footer, x, size - 80);
}

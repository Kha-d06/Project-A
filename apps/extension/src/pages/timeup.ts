import { byId } from "../lib/dom";
import { initLanguage, localizeDocument, t } from "../lib/i18n";
import { loadSettings } from "../lib/settings";
import { applyTheme } from "../lib/theme";

async function main() {
  await Promise.all([initLanguage(), applyTheme()]);
  localizeDocument();
  const settings = await loadSettings();
  const s = t().timeup;
  const rule = settings.screenTime;
  const reason = settings.screenTimeBlocked ?? new URLSearchParams(location.search).get("r");
  const outside = reason === "outside_hours";
  byId("headline").textContent = outside ? s.outsideTitle : s.limitTitle;
  document.title = outside ? s.outsideTitle : s.limitTitle;
  byId("detail").textContent = outside ? s.outsideDetail : s.limitDetail;
  const parts: string[] = [];
  if (rule?.allowed_from && rule.allowed_until) parts.push(s.window(rule.allowed_from, rule.allowed_until));
  if (rule?.daily_minutes) parts.push(s.limit(rule.daily_minutes));
  byId("rule").textContent = parts.join(" ");
}

void main();

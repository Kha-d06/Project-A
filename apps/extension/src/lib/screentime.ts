/**
 * Family screen time, for members who chose to follow a family group's rules.
 *
 * The rule comes from the linked account: an allowed window ("07:00"–"20:00") and a
 * daily minute limit. A minute counts only while the computer is in use and a
 * browser window showing a web page has focus. Only the day's total ever leaves
 * the browser, never which sites were open.
 *
 * Outside the window, or once the limit is used up, rule 10 blocks web pages in
 * the browser itself (a block rule needs no host permissions) and the tab shows
 * Qalaa's time's-up page. The rule stays on while checks are paused, like
 * SafeSearch, because it is a family rule.
 *
 * Honest limit: this covers browsing in browsers where Qalaa Protect is installed
 * and linked. It does not see other apps or other browsers.
 */

export interface ScreenTimeRule {
  allowed_from: string | null;
  allowed_until: string | null;
  daily_minutes: number;
}

export interface ScreenTimeUsage {
  day: string;
  minutes: number;
  /** Minutes already sent to the server for this day. */
  reported: number;
}

export type BlockReason = "outside_hours" | "limit_reached";

export const RULE_SCREEN_TIME = 10;
export const SCREEN_TIME_ALARM = "screen-time";
/** Send the day's total at most this often (minutes of use), and when the limit is reached. */
export const REPORT_EVERY = 5;
export const USAGE_KEY = "screenTimeUsage";

/** The local calendar day, as YYYY-MM-DD. */
export function dayKey(now: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

function clock(value: string): number | null {
  const match = /^(\d{2}):(\d{2})$/.exec(value);
  if (!match) return null;
  const minutes = Number(match[1]) * 60 + Number(match[2]);
  return minutes <= 24 * 60 ? minutes : null;
}

/** True when browsing is allowed at this time of day. No window means any time. */
export function inWindow(rule: ScreenTimeRule, now: Date): boolean {
  if (!rule.allowed_from || !rule.allowed_until) return true;
  const from = clock(rule.allowed_from);
  const until = clock(rule.allowed_until);
  if (from === null || until === null) return true;
  const minute = now.getHours() * 60 + now.getMinutes();
  return minute >= from && minute < until;
}

/** Why browsing is blocked right now, or null when it is allowed. */
export function blockReason(rule: ScreenTimeRule | null, usage: ScreenTimeUsage, now: Date): BlockReason | null {
  if (!rule) return null;
  if (!inWindow(rule, now)) return "outside_hours";
  const used = usage.day === dayKey(now) ? usage.minutes : 0;
  if (rule.daily_minutes > 0 && used >= rule.daily_minutes) return "limit_reached";
  return null;
}

/** Adds one minute of use, starting again on a new day. */
export function addMinute(usage: ScreenTimeUsage, now: Date): ScreenTimeUsage {
  const day = dayKey(now);
  if (usage.day !== day) return { day, minutes: 1, reported: 0 };
  return { ...usage, minutes: Math.min(usage.minutes + 1, 24 * 60) };
}

/** Today's usage, or an empty day. */
export function usageFor(usage: ScreenTimeUsage | undefined, now: Date): ScreenTimeUsage {
  const day = dayKey(now);
  return usage && usage.day === day ? usage : { day, minutes: 0, reported: 0 };
}

export function shouldReport(usage: ScreenTimeUsage, rule: ScreenTimeRule): boolean {
  if (usage.minutes <= usage.reported) return false;
  const reachedLimit = rule.daily_minutes > 0 && usage.minutes >= rule.daily_minutes;
  return reachedLimit || usage.minutes - usage.reported >= REPORT_EVERY;
}

/** Blocks every web page except Qalaa's own server, above the allow list. */
export function screenTimeBlockRule(serverHost: string | null): chrome.declarativeNetRequest.Rule {
  return {
    id: RULE_SCREEN_TIME,
    priority: 4,
    action: { type: "block" as chrome.declarativeNetRequest.RuleActionType },
    condition: {
      regexFilter: "^https?://",
      resourceTypes: ["main_frame"] as chrome.declarativeNetRequest.ResourceType[],
      ...(serverHost ? { excludedRequestDomains: [serverHost] } : {}),
    },
  };
}

export function sameRule(a: ScreenTimeRule | null, b: ScreenTimeRule | null): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

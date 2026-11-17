/**
 * Well-known advertising and analytics domains, matched against the hosts a page
 * loads resources from. A short, hand-picked list: it names the big players
 * people recognise rather than trying to be a full blocklist.
 */
export interface Tracker {
  name: string;
  category: "advertising" | "analytics" | "social" | "session_recording";
}

const TRACKERS: Record<string, Tracker> = {
  "google-analytics.com": { name: "Google Analytics", category: "analytics" },
  "googletagmanager.com": { name: "Google Tag Manager", category: "analytics" },
  "doubleclick.net": { name: "Google advertising (DoubleClick)", category: "advertising" },
  "googlesyndication.com": { name: "Google AdSense", category: "advertising" },
  "googleadservices.com": { name: "Google Ads", category: "advertising" },
  "adservice.google.com": { name: "Google Ads", category: "advertising" },
  "facebook.net": { name: "Meta Pixel", category: "advertising" },
  "connect.facebook.net": { name: "Meta Pixel", category: "advertising" },
  "analytics.tiktok.com": { name: "TikTok Pixel", category: "advertising" },
  "snap.licdn.com": { name: "LinkedIn Insight", category: "advertising" },
  "ads.linkedin.com": { name: "LinkedIn Ads", category: "advertising" },
  "static.ads-twitter.com": { name: "X (Twitter) Ads", category: "advertising" },
  "analytics.twitter.com": { name: "X (Twitter) Analytics", category: "advertising" },
  "sc-static.net": { name: "Snapchat Pixel", category: "advertising" },
  "bat.bing.com": { name: "Microsoft Advertising", category: "advertising" },
  "clarity.ms": { name: "Microsoft Clarity", category: "session_recording" },
  "hotjar.com": { name: "Hotjar", category: "session_recording" },
  "fullstory.com": { name: "FullStory", category: "session_recording" },
  "mouseflow.com": { name: "Mouseflow", category: "session_recording" },
  "segment.com": { name: "Segment", category: "analytics" },
  "segment.io": { name: "Segment", category: "analytics" },
  "mixpanel.com": { name: "Mixpanel", category: "analytics" },
  "amplitude.com": { name: "Amplitude", category: "analytics" },
  "heap.io": { name: "Heap", category: "analytics" },
  "newrelic.com": { name: "New Relic", category: "analytics" },
  "nr-data.net": { name: "New Relic", category: "analytics" },
  "scorecardresearch.com": { name: "Comscore", category: "analytics" },
  "quantserve.com": { name: "Quantcast", category: "advertising" },
  "criteo.com": { name: "Criteo", category: "advertising" },
  "criteo.net": { name: "Criteo", category: "advertising" },
  "taboola.com": { name: "Taboola", category: "advertising" },
  "outbrain.com": { name: "Outbrain", category: "advertising" },
  "adnxs.com": { name: "Xandr (AppNexus)", category: "advertising" },
  "rubiconproject.com": { name: "Magnite", category: "advertising" },
  "pubmatic.com": { name: "PubMatic", category: "advertising" },
  "amazon-adsystem.com": { name: "Amazon Ads", category: "advertising" },
  "yandex.ru": { name: "Yandex Metrica", category: "analytics" },
  "mc.yandex.ru": { name: "Yandex Metrica", category: "analytics" },
  "hubspot.com": { name: "HubSpot", category: "analytics" },
  "hs-analytics.net": { name: "HubSpot", category: "analytics" },
  "intercom.io": { name: "Intercom", category: "analytics" },
  "optimizely.com": { name: "Optimizely", category: "analytics" },
  "branch.io": { name: "Branch", category: "advertising" },
  "appsflyer.com": { name: "AppsFlyer", category: "advertising" },
  "adjust.com": { name: "Adjust", category: "advertising" },
};

/** Tracker domains, for optional blocking with declarativeNetRequest. */
export const TRACKER_DOMAINS = Object.keys(TRACKERS);

export function trackerFor(host: string): Tracker | null {
  const lower = host.toLowerCase();
  const parts = lower.split(".");
  for (let i = 0; i < parts.length - 1; i += 1) {
    const candidate = parts.slice(i).join(".");
    if (TRACKERS[candidate]) return TRACKERS[candidate];
  }
  return null;
}

/** Unique tracker names among the given hosts, in a stable order. */
export function detectTrackers(hosts: string[]): Tracker[] {
  const found = new Map<string, Tracker>();
  for (const host of hosts) {
    const tracker = trackerFor(host);
    if (tracker && !found.has(tracker.name)) found.set(tracker.name, tracker);
  }
  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** Registrable-domain approximation: last two labels, or three for two-letter
 * second levels such as co.uk / com.sa. Good enough to tell first from third party. */
export function siteOf(host: string): string {
  const parts = host.toLowerCase().replace(/^\./, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  const second = parts[parts.length - 2] ?? "";
  const take = second.length <= 3 && ["co", "com", "net", "org", "gov", "edu", "ac"].includes(second) ? 3 : 2;
  return parts.slice(-take).join(".");
}

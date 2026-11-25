/**
 * Build step: EasyList and EasyPrivacy compiled into static declarativeNetRequest
 * rulesets (rules/*.json), disabled until the person turns "Block ads and
 * trackers" on.
 *
 * The lists are by The EasyList authors (https://easylist.to/), dual-licensed
 * GPLv3 / CC BY-SA 3.0. The compiled rulesets are distributed under CC BY-SA
 * 3.0 with attribution in rules/NOTICE.txt; Qalaa's own code isn't affected.
 *
 * Lists come from FILTER_LIST_DIR if set, else a fresh download (cached in
 * .cache/filter-lists for a day). If neither works the build continues without
 * the rulesets and the feature shows as unavailable.
 */
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { convertList } from "./abp-dnr.mjs";

export const LISTS = [
  { id: "easylist", title: "EasyList", url: "https://easylist.to/easylist/easylist.txt", cap: 20000 },
  { id: "easyprivacy", title: "EasyPrivacy", url: "https://easylist.to/easylist/easyprivacy.txt", cap: 10000 },
];
const DAY = 24 * 60 * 60 * 1000;

async function source(root, list) {
  if (process.env.FILTER_LIST_DIR) return readFile(join(process.env.FILTER_LIST_DIR, `${list.id}.txt`), "utf8");
  const cacheDir = join(root, ".cache", "filter-lists");
  const cached = join(cacheDir, `${list.id}.txt`);
  const fresh = await stat(cached).then((s) => Date.now() - s.mtimeMs < DAY, () => false);
  if (fresh) return readFile(cached, "utf8");
  const response = await fetch(list.url, { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`${list.url}: HTTP ${response.status}`);
  const text = await response.text();
  if (!/^\[Adblock Plus|^! Title:/m.test(text.slice(0, 1000))) throw new Error(`${list.url} isn't a filter list`);
  await mkdir(cacheDir, { recursive: true });
  await writeFile(cached, text);
  return text;
}

/** Writes rules/<id>.json and NOTICE.txt into `out`; returns manifest rule_resources (possibly empty). */
export async function buildFilterRulesets(root, out) {
  const resources = [];
  const notes = [];
  await mkdir(join(out, "rules"), { recursive: true });
  for (const list of LISTS) {
    let text;
    try {
      text = await source(root, list);
    } catch (error) {
      console.warn(`Filter list ${list.id} unavailable, building without it: ${error.message}`);
      continue;
    }
    const version = /^! Version: (.+)$/m.exec(text)?.[1]?.trim() ?? "unknown";
    const { rules, report } = convertList(text, { cap: list.cap });
    await writeFile(join(out, "rules", `${list.id}.json`), JSON.stringify(rules));
    resources.push({ id: list.id, enabled: false, path: `rules/${list.id}.json` });
    notes.push(`${list.title} (version ${version}), ${list.url}\n  ${rules.length} network rules converted; ${Object.values(report.skipped).reduce((a, b) => a + b, 0)} not convertible (cosmetic, regex or unsupported options), ${report.capped} over the cap.`);
  }
  if (resources.length) {
    await writeFile(
      join(out, "rules", "NOTICE.txt"),
      [
        "The rule files in this folder are converted from filter lists by The EasyList authors (https://easylist.to/).",
        "They are licensed under the Creative Commons Attribution-ShareAlike 3.0 Unported licence",
        "(https://creativecommons.org/licenses/by-sa/3.0/). Converted to declarativeNetRequest format by Qalaa's build.",
        "",
        ...notes,
        "",
      ].join("\n"),
    );
  }
  return resources;
}

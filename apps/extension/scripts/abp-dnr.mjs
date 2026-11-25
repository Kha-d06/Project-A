/**
 * Adblock Plus / uBlock network rules -> Chrome declarativeNetRequest rules,
 * at build time. Pure: text in, rules and a report out (tested in
 * test/abp-dnr.test.ts).
 *
 * DNR's urlFilter speaks the same `||`, `|`, `^` and `*` as Adblock Plus, so
 * patterns carry over as they are. Options carried over: $third-party /
 * $first-party, $domain= (with ~exclusions), resource types (and ~types),
 * $match-case, $important (higher priority), @@ exceptions (allow), and
 * @@...$document (allowAllRequests). Everything else is skipped and counted,
 * never guessed: cosmetic (##), scriptlets, regular expressions, $redirect,
 * $csp, $removeparam and the like. $badfilter removes the rule it names.
 *
 * Chrome guarantees 30,000 enabled static rules per extension, so each list
 * has a cap; exceptions come first, then whole-host rules, then the rest.
 */

const TYPES = {
  script: "script",
  image: "image",
  stylesheet: "stylesheet",
  css: "stylesheet",
  object: "object",
  xmlhttprequest: "xmlhttprequest",
  xhr: "xmlhttprequest",
  subdocument: "sub_frame",
  frame: "sub_frame",
  ping: "ping",
  beacon: "ping",
  media: "media",
  font: "font",
  websocket: "websocket",
  other: "other",
  document: "main_frame",
  doc: "main_frame",
};
const IGNORED_OPTIONS = new Set(["all", "1p", "3p", "first-party", "third-party", "match-case", "important", "domain", "badfilter"]);
const UNSUPPORTED = /^(redirect|redirect-rule|csp|removeparam|queryprune|rewrite|replace|popup|popunder|generichide|elemhide|ehide|specifichide|shide|genericblock|inline-script|inline-font|cname|permissions|header|to|from|method|denyallow|strict1p|strict3p|urltransform|uritransform|empty|mp4|webrtc|object-subrequest|ipaddress|app|network|extension|content|jsinject|urlblock|stealth|cookie|hls|jsonprune|xmlprune|referrerpolicy|sitekey|rewrite)$/;

function parseOptions(text) {
  // Options start at the last '$' that isn't part of the pattern (patterns never contain ',' after '$').
  const at = text.lastIndexOf("$");
  if (at <= 0 || /[/^|*]$/.test(text.slice(at + 1)) || text.slice(at + 1).includes("/")) return { pattern: text, options: [] };
  return { pattern: text.slice(0, at), options: text.slice(at + 1).split(",").map((o) => o.trim()).filter(Boolean) };
}

function asciiDomain(d) {
  return /^[a-z0-9.*-]+$/i.test(d) && d.includes(".") ? d.toLowerCase() : null;
}

/** One line -> { rule } | { skip: reason } | null (comment/blank). */
export function convertLine(line) {
  const t = line.trim();
  if (!t || t.startsWith("!") || t.startsWith("[")) return null;
  if (/#[@?$%]?#|#\+js|\$\$|##\^/.test(t)) return { skip: "cosmetic" };
  let text = t;
  const exception = text.startsWith("@@");
  if (exception) text = text.slice(2);
  const { pattern, options } = parseOptions(text);
  if (pattern.startsWith("/") && pattern.endsWith("/") && pattern.length > 2) return { skip: "regex" };
  if (!pattern || pattern === "*" || pattern === "|" || pattern === "||") return { skip: "too_broad" };
  if (!/^[\x21-\x7e]+$/.test(pattern)) return { skip: "non_ascii" };

  const condition = {};
  const types = [];
  const excludedTypes = [];
  let priority = exception ? 2 : 1;
  let badfilter = false;
  let document = false;
  for (const raw of options) {
    const negated = raw.startsWith("~");
    const [name, value] = (negated ? raw.slice(1) : raw).split("=", 2);
    const key = name.toLowerCase();
    if (UNSUPPORTED.test(key)) return { skip: `option:${key}` };
    if (key === "badfilter") badfilter = true;
    else if (key === "important") priority = exception ? 4 : 3;
    else if (key === "match-case") condition.isUrlFilterCaseSensitive = true;
    else if (key === "third-party" || key === "3p") condition.domainType = negated ? "firstParty" : "thirdParty";
    else if (key === "first-party" || key === "1p") condition.domainType = negated ? "thirdParty" : "firstParty";
    else if (key === "domain") {
      const inc = [];
      const exc = [];
      for (const d of (value ?? "").split("|")) {
        const dom = asciiDomain(d.replace(/^~/, ""));
        if (!dom || dom.includes("*")) return { skip: "domain_wildcard" };
        (d.startsWith("~") ? exc : inc).push(dom);
      }
      if (inc.length) condition.initiatorDomains = inc;
      if (exc.length) condition.excludedInitiatorDomains = exc;
    } else if (key in TYPES) {
      if (TYPES[key] === "main_frame" && !negated) document = true;
      (negated ? excludedTypes : types).push(TYPES[key]);
    } else if (!IGNORED_OPTIONS.has(key)) return { skip: `option:${key}` };
  }
  condition.urlFilter = pattern;
  if (types.length) condition.resourceTypes = [...new Set(types)];
  if (excludedTypes.length) condition.excludedResourceTypes = [...new Set(excludedTypes)];
  let action = { type: exception ? "allow" : "block" };
  if (exception && document) {
    action = { type: "allowAllRequests" };
    condition.resourceTypes = ["main_frame", "sub_frame"];
  }
  return { rule: { priority, action, condition }, badfilter, key: `${exception ? "@@" : ""}${text}`.replace(/,?badfilter/, "").replace(/\$$/, "") };
}

function rank(rule) {
  if (rule.action.type !== "block") return 0; // exceptions first: dropping one would break a site
  return /^\|\|[a-z0-9.-]+\^$/i.test(rule.condition.urlFilter) ? 1 : 2; // whole-host rules next
}

/** A whole list -> { rules, report }. Rule ids start at 1 within each ruleset. */
export function convertList(text, { cap = 20000 } = {}) {
  const report = { lines: 0, converted: 0, skipped: {}, badfilter: 0, capped: 0 };
  const converted = [];
  const bad = new Set();
  for (const line of text.split(/\r?\n/)) {
    const result = convertLine(line);
    if (!result) continue;
    report.lines += 1;
    if (result.skip) {
      report.skipped[result.skip] = (report.skipped[result.skip] ?? 0) + 1;
      continue;
    }
    if (result.badfilter) {
      bad.add(result.key);
      report.badfilter += 1;
      continue;
    }
    converted.push(result);
  }
  const kept = converted.filter((c) => !bad.has(c.key)).map((c) => c.rule);
  kept.sort((a, b) => rank(a) - rank(b));
  report.capped = Math.max(0, kept.length - cap);
  const rules = kept.slice(0, cap).map((r, i) => ({ id: i + 1, ...r }));
  report.converted = rules.length;
  return { rules, report };
}

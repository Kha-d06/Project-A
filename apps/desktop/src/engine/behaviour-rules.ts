/**
 * Process-creation behaviour rules, a small subset of the Sigma format.
 *
 * Rules live in core/data/behaviour-rules.json. Most are adapted from
 * SigmaHQ's process_creation rules (Detection Rule License 1.1: each rule
 * keeps its source and author in `sigma`). Supported:
 *
 *   fields      Image, CommandLine, ParentImage, ParentCommandLine
 *   modifiers   contains, startswith, endswith, re, and |all on any of them
 *   condition   "selection", "selection and not filter",
 *               "1 of selection_*", "1 of selection_* and not filter"
 *
 * Values match case-insensitively, as Sigma's do. Pure and deterministic, so
 * every rule is tested against recorded events.
 */

export interface ProcessEvent {
  pid: number;
  ppid: number;
  /** Full path of the executable when known, otherwise argv[0]. */
  image: string;
  commandLine: string;
  parentImage: string;
  parentCommandLine: string;
  at: number;
}

type Field = "Image" | "CommandLine" | "ParentImage" | "ParentCommandLine";
type Selection = Record<string, string | string[]>;

export interface BehaviourRule {
  id: string;
  title: string;
  /** What it means, in plain words, for the alert. */
  description: string;
  technique: string;
  level: "low" | "medium" | "high" | "critical";
  platforms: ("linux" | "macos" | "windows")[];
  /** Where it came from: a SigmaHQ rule (DRL 1.1) or "qalaa". */
  sigma: { id?: string; title?: string; author?: string; source: string };
  detection: Record<string, Selection | string>;
  falsepositives?: string[];
}

const FIELDS: Record<Field, keyof ProcessEvent> = {
  Image: "image",
  CommandLine: "commandLine",
  ParentImage: "parentImage",
  ParentCommandLine: "parentCommandLine",
};

const MODIFIERS = new Set(["contains", "startswith", "endswith", "re", "all"]);

function matchOne(value: string, needle: string, op: string): boolean {
  const v = value.toLowerCase();
  const n = needle.toLowerCase();
  switch (op) {
    case "contains":
      return v.includes(n);
    case "startswith":
      return v.startsWith(n);
    case "endswith":
      return v.endsWith(n);
    case "re":
      return new RegExp(needle, "i").test(value);
    default:
      return v === n;
  }
}

function matchSelection(event: ProcessEvent, selection: Selection): boolean {
  return Object.entries(selection).every(([key, raw]) => {
    const [field, ...mods] = key.split("|");
    const prop = FIELDS[field as Field];
    if (!prop) return false;
    const value = String(event[prop] ?? "");
    const op = mods.find((m) => m !== "all") ?? "equals";
    const values = Array.isArray(raw) ? raw : [raw];
    return mods.includes("all") ? values.every((n) => matchOne(value, n, op)) : values.some((n) => matchOne(value, n, op));
  });
}

/** Throws on anything this evaluator doesn't support, so a bad rule fails its test, not silently. */
export function validateRule(rule: BehaviourRule): void {
  if (!/^[a-z0-9_]+$/.test(rule.id)) throw new Error(`${rule.id}: bad id`);
  if (!/^T\d{4}(\.\d{3})?$/.test(rule.technique)) throw new Error(`${rule.id}: bad technique`);
  if (!rule.title || !rule.description || !rule.platforms.length) throw new Error(`${rule.id}: incomplete`);
  if (!rule.sigma?.source) throw new Error(`${rule.id}: no source`);
  const condition = rule.detection.condition;
  if (typeof condition !== "string" || !/^(selection|1 of selection_\*)( and not filter)?$/.test(condition)) throw new Error(`${rule.id}: unsupported condition ${String(condition)}`);
  for (const [name, sel] of Object.entries(rule.detection)) {
    if (name === "condition") continue;
    if (typeof sel !== "object") throw new Error(`${rule.id}: ${name} is not a selection`);
    for (const key of Object.keys(sel)) {
      const [field, ...mods] = key.split("|");
      if (!(field! in FIELDS)) throw new Error(`${rule.id}: unknown field ${field}`);
      for (const m of mods) if (!MODIFIERS.has(m)) throw new Error(`${rule.id}: unknown modifier ${m}`);
      if (mods.includes("re")) for (const v of [sel[key]].flat()) new RegExp(v!, "i");
    }
  }
  if (condition.startsWith("1 of") && !Object.keys(rule.detection).some((k) => k.startsWith("selection_"))) throw new Error(`${rule.id}: no selection_*`);
  if (condition.includes("filter") && typeof rule.detection.filter !== "object") throw new Error(`${rule.id}: no filter`);
}

export function matches(rule: BehaviourRule, event: ProcessEvent): boolean {
  const d = rule.detection;
  const condition = String(d.condition);
  const selections = condition.startsWith("1 of")
    ? Object.entries(d).filter(([k]) => k.startsWith("selection_")).map(([, v]) => v as Selection)
    : [d.selection as Selection];
  if (!selections.some((s) => matchSelection(event, s))) return false;
  if (condition.endsWith("and not filter") && matchSelection(event, d.filter as Selection)) return false;
  return true;
}

export function rulesFor(rules: BehaviourRule[], platform: NodeJS.Platform): BehaviourRule[] {
  const name = platform === "darwin" ? "macos" : platform === "win32" ? "windows" : "linux";
  return rules.filter((r) => r.platforms.includes(name));
}

/**
 * Command lines can hold secrets (tokens, passwords). Only a shortened,
 * masked copy is kept: long random-looking strings and values after
 * password/token flags are replaced.
 */
export function redactCommandLine(cmd: string, max = 300): string {
  return cmd
    .replace(/(--?(?:p|pass|password|passwd|token|secret|key|api[-_]?key)[= ])\S+/gi, "$1•••")
    .replace(/([?&](?:token|key|sig|password)=)[^&\s]+/gi, "$1•••")
    .replace(/\b[A-Za-z0-9+/_=-]{32,}\b/g, "•••")
    .slice(0, max);
}

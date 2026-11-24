// Types for analysis.js, so the desktop app (TypeScript) can import it.
export interface EmailFields {
  from_header: string;
  reply_to: string | null;
  subject: string;
  authentication_results: string;
  text: string;
  links: { href: string; text: string }[];
}
export interface RulePack {
  version: string;
  rules: { category: string; severity: string; title: string; explanation: string; title_ar: string; explanation_ar: string; patterns: string[] }[];
  brands: Record<string, { name: string; domains: string[] }>;
  shorteners: string[];
}
export type CompiledPack = RulePack & { rules: (RulePack["rules"][number] & { compiled: RegExp[] })[] };
export interface Finding {
  severity: string;
  category: string;
  title: string;
  explanation: string;
  excerpt?: string;
  link?: string;
}
export interface LinkResult {
  url: string;
  host: string;
  findings: { severity: string; title: string; explanation: string }[];
}
export function siteOf(host: string): string;
export function parseAddress(header: string): { name: string; address: string; domain: string };
export function authResults(header: string): Record<string, string>;
export function bareUrl(raw: string): string | null;
export function linksToCheck(email: Pick<EmailFields, "links" | "text">): string[];
export function compilePack(pack: RulePack | null | undefined): CompiledPack | null;
export function analyzeLocally(email: EmailFields, pack: CompiledPack | null, lang?: "en" | "ar"): Finding[];
export function linkReputationFindings(results: LinkResult[]): Finding[];
export function verdict(findings: Finding[], lang?: "en" | "ar"): { risk: "known_malicious" | "suspicious" | "no_known_threat"; summary: string; findings: Finding[] };

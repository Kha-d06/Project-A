/**
 * SafePay offer: on banking and payment sites, Qalaa offers to reopen the page
 * in SafePay, a clean browser session the desktop app starts (fresh profile,
 * no extensions, deleted on close). The page is handed over as a
 * qalaa://safepay link, so the browser asks the person before Qalaa Desktop
 * sees it, and the desktop app accepts https pages only.
 */

/** Well-known banks and payment services (subdomains included). */
export const BANKING_DOMAINS = [
  // Gulf
  "emiratesnbd.com", "adcb.com", "bankfab.com", "mashreq.com", "rakbank.ae", "dib.ae", "adib.ae", "cbd.ae", "enbd.com",
  "alrajhibank.com.sa", "alahli.com", "riyadbank.com", "sab.com", "alinma.com", "bankalbilad.com", "anb.com.sa",
  "nbk.com", "kfh.com", "qnb.com", "cbq.qa", "bankmuscat.com", "ahlibank.com.om", "nbb.com.bh", "bisb.com",
  // Elsewhere
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "capitalone.com", "usbank.com", "americanexpress.com",
  "hsbc.com", "hsbc.co.uk", "barclays.co.uk", "lloydsbank.com", "natwest.com", "santander.co.uk", "monzo.com",
  "deutsche-bank.de", "bnpparibas.net", "ing.com", "commbank.com.au",
  // Payments
  "paypal.com", "wise.com", "revolut.com", "stripe.com",
];

const BANKING_LABEL = /(^|[.-])(e?bank|banking|netbank|ibank|onlinebanking)([.-]|$)/;

export function isBankingHost(host: string, extra: readonly string[] = []): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if ([...BANKING_DOMAINS, ...extra].some((d) => h === d || h.endsWith(`.${d}`))) return true;
  // "onlinebanking.example", "ebank.example", "bank.example": a label that says bank.
  return BANKING_LABEL.test(h.split(".").slice(0, -1).join("."));
}

/** The link the desktop app opens; null for anything but an https page. */
export function safePayLink(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "https:" || u.username || u.password) return null;
    return `qalaa://safepay?url=${encodeURIComponent(u.toString())}`;
  } catch {
    return null;
  }
}

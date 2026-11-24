/**
 * /llms.txt and /llms-full.txt: plain Markdown for AI crawlers and answer
 * engines. Facts only, including what Qalaa does not do; keep in step with the
 * product (the tests check both files name every platform and its limits).
 */
import { PUBLIC_PAGES, siteUrl } from "./seo";

const link = (path: string, name: string) => `[${name}](${siteUrl()}${path === "/" ? "" : path})`;

export function llmsTxt(): string {
  return `# Qalaa

> Qalaa is a free security suite, in English and Arabic, that checks links, messages and files for phishing, scams and malware and explains what it found in plain language. Every feature is free; there is no paid tier.

Qalaa reports "no known threat detected" rather than calling anything safe: a clean result means no check found a known problem, not a guarantee.

## Pages

${PUBLIC_PAGES.map((p) => `- ${link(p.path, p.en)}`).join("\n")}

## More

- ${link("/llms-full.txt", "Full description: features, platforms, privacy and limits")}
`;
}

export function llmsFullTxt(): string {
  return `# Qalaa: full description

> A free, bilingual (English and Arabic) security suite. Web app, browser extension (Chrome, Edge, Firefox), Thunderbird add-on, desktop app (Windows, macOS, Linux) and Android app. Source of these facts: ${siteUrl()}.

## What it does

- **Check a link, message or file** (${siteUrl()}/scan): reputation from threat feeds (URLhaus, ThreatFox, MalwareBazaar, OpenPhish) and moderator-verified community reports, look-alike and brand-impersonation checks, scam-wording patterns in English and Arabic, and file inspection without opening or running the file.
- **Browser extension**: blocks domains on the threat list before the page loads, warns about look-alike sites, optional tracker blocking, family block lists and screen-time rules for members who choose to follow them.
- **Email**: a Thunderbird add-on and the desktop app's inbox scanner check each message on the device; only the message's links (without query strings) are sent for a threat-list lookup.
- **Desktop app**: malware scanning with quarantine, on-access blocking on Linux (fanotify), ransomware behaviour blocking, Windows Controlled Folder Access, home network scanner, new listening-port alerts, new-keyboard (BadUSB) warnings, Safe DNS over DNS-over-HTTPS, Secure Boot / TPM / disk-encryption / patch-age checks, WireGuard VPN with kill switch, encrypted backups.
- **Password manager**: end-to-end encrypted vault with passkeys, TOTP codes, sharing with family and emergency access. The server stores only ciphertext.
- **Families and organisations**: shared block lists and rules, compliance views and exports; members see the rules and can leave them.

## Platforms

| Platform | Status |
|---|---|
| Web | Available |
| Chrome, Edge, Firefox | Browser extension |
| Thunderbird 128+ | Add-on |
| Windows | Desktop app |
| macOS | Desktop app |
| Linux | Desktop app (on-access blocking needs fanotify) |
| Android | App |
| iOS | Web app only |

## Privacy

- Background checks never send message bodies, email headers or file contents. File reputation uses k-anonymity: only the first 6 characters of a file's SHA-256 are sent and the match is made on the device.
- Lookups that run without the person asking are left out of the server's access log.
- Account features are optional; scans can be run without an account.

## Limits (stated, not hidden)

- "No known threat detected" is not a guarantee: new phishing sites can go unreported for hours or days.
- Qalaa is a second opinion, not a replacement for the security built into a device.
- No kernel drivers on Windows or macOS: protection there uses the operating system's own security features.
- Family screen time covers browsers where the extension is installed and linked, not other apps.
- No paid data brokers, credit monitoring or identity insurance.
`;
}

import type { Metadata } from "next";

import Link from "next/link";

import { ProsePage } from "@/components/site/prose";
import { getLocale } from "@/lib/i18n/server";

import { PrivacyArabic } from "./privacy-ar";

export const metadata: Metadata = { title: "Privacy" };

export default async function PrivacyPage() {
  if ((await getLocale()) === "ar") return <PrivacyArabic />;
  return (
    <ProsePage
      title="Privacy"
      intro="What SENTINEL stores, for how long, and who else ever sees it."
    >
      <section>
        <h2>What we store</h2>
        <ul>
          <li><strong>Link scans:</strong> the link, the redirect chain, and the report.</li>
          <li><strong>Message scans:</strong> the first 80 characters of the message as a label, the links, email addresses and phone numbers found in it, and the report. The full text is discarded when the analysis finishes.</li>
          <li><strong>QR, website and app scans:</strong> what was decoded or found (for example the page title, form addresses, or an app’s package name and permissions) and the report. Uploaded images and apps are deleted as soon as the scan finishes.</li>
          <li><strong>File scans:</strong> the file name, size, type, SHA-256 fingerprint and the report. The file itself is deleted as soon as the scan finishes, whatever the outcome.</li>
          <li><strong>Accounts:</strong> your email address, an optional display name, a salted Argon2 hash of your password, and a log of sign-ins and security changes with the IP address they came from.</li>
        </ul>
      </section>
      <section>
        <h2>How long we keep it</h2>
        <ul>
          <li>Scans made without an account are deleted after 30 days.</li>
          <li>Scans saved to an account stay until you delete them or the account.</li>
          <li>Sessions expire after 7 days.</li>
        </ul>
      </section>
      <section>
        <h2>Who else sees it</h2>
        <p>
          Threat feeds are downloaded to our server and matched there, so links and fingerprints you
          check are not sent to the feed providers. Two checks do contact outside services:
        </p>
        <ul>
          <li><strong>Redirect tracing</strong> requests the link you submitted from our server, so the website you are checking will see a request from SENTINEL (not from you).</li>
          <li><strong>Domain age</strong> sends the domain name (not the full link) to rdap.org and the domain’s registry.</li>
          <li><strong>Website analysis</strong> downloads the page (up to 2 MB of HTML) from our server and looks up the domain’s DNS and email-protection (SPF, DMARC) records. If the operator has turned on isolated rendering, the page is also opened in a sealed browser on our server, which cannot reach private networks and is not allowed to send form data anywhere.</li>
          <li><strong>Certificate history</strong> sends the domain name to crt.sh, a public log of security certificates.</li>
          <li>If the operator has configured Google Web Risk, the link is also sent to Google.</li>
          <li>If the operator has configured a live URLhaus key, the link is also sent to abuse.ch. The <Link href="/#integrations">integrations list</Link> shows whether that is the case.</li>
          <li><strong>AI explanations</strong> are only created when you ask for one. Then the verdict and the summaries of the findings are sent to the AI provider (OpenAI). Your message text, files and full addresses are not.</li>
          <li><strong>AI second opinion on a message</strong> is off unless you tick the box for that scan. The message is then sent to the AI provider with links, email addresses and numbers masked.</li>
          <li><strong>AI reading of screenshots</strong> is off unless you tick the box for that scan. The image, re-encoded without its metadata, is then sent to the AI provider to transcribe its text, links and numbers.</li>
          <li><strong>VirusTotal</strong> is off unless you tick the box for that scan. Only the file’s SHA-256 fingerprint is sent, never the file.</li>
          <li>If the operator runs MobSF for deeper app analysis, uploaded apps are sent to that server, which belongs to the operator.</li>
        </ul>
        <p>Uploaded files themselves are never sent to any third party.</p>
      </section>
      <section>
        <h2>The browser extension</h2>
        <ul>
          <li>For each page you open, SENTINEL Protect sends its address (or, in privacy mode, only the domain) to the SENTINEL server. The server answers from its local threat database and stores nothing about the request.</li>
          <li>It never sends page content, form contents, passwords or messages. Private-network and local addresses are not sent at all.</li>
          <li>It downloads SENTINEL’s whole list of known dangerous domains every few hours, so blocking them before they load reveals nothing about your browsing.</li>
          <li>If you turn on the on-screen assistant, it reads the names of cookies (never their values) and the domains of trackers a page loads, and shows them to you. When you ask it a question, the question, the site’s domain, its verdict, the warning titles and those cookie and tracker names are sent to the SENTINEL server, and on to the AI provider if the operator has configured one.</li>
          <li>Recent alerts, your lists and settings are stored only in your browser.</li>
          <li>If you link it to an account and turn on warning history, the domain, the verdict and what you chose are saved to your account. You can delete that history at any time.</li>
        </ul>
      </section>
      <section>
        <h2>Linked devices</h2>
        <ul>
          <li>When you link SENTINEL Desktop or the Android app to your account, the device sends a heartbeat about every 30 seconds while it runs: its name, platform, app version, whether remote scans are allowed, the names of the folders it offers (for example “Downloads”, never their full paths) and a short protection summary (for example whether real-time protection is on).</li>
          <li><strong>Remote scans are off until you turn them on in the app on that device.</strong> When they are on, anyone signed in to your account can start a scan, quarantine a file a scan found, or update the fingerprint list there. Nobody can open, upload, copy or delete your files from the website.</li>
          <li>Scan results sent back contain file names, the label of the folder they were in, verdicts and SHA-256 fingerprints. File contents and full paths stay on the device.</li>
          <li>SENTINEL Desktop’s security centre (firewall, open ports, startup programs, camera and microphone use) runs entirely on the computer. A linked computer reports only whether its firewall is on, how many risky services are open to the network, and when it last made a backup.</li>
          <li>Encrypted backups are written where you choose, never to SENTINEL. Their password never leaves the computer.</li>
          <li>Only the last 50 commands per device are kept. Removing a device from your account deletes its records and signs the app out.</li>
        </ul>
      </section>
      <section>
        <h2>Password manager</h2>
        <ul>
          <li>Your vault is encrypted in your browser with a key made from your master password before it is saved. SENTINEL stores only the encrypted result and cannot read your passwords, notes, the sites they belong to, or even how many you have (the size is rounded up).</li>
          <li>Your master password is never sent to SENTINEL, so it cannot be reset or recovered.</li>
          <li>The breach check sends only the first five characters of each password’s SHA-1 fingerprint to Have I Been Pwned, from your browser.</li>
          <li>Deleting the vault, or your account, removes the encrypted copy from SENTINEL.</li>
        </ul>
      </section>
      <section>
        <h2>Sharing, groups, bots and email</h2>
        <ul>
          <li><strong>Share links</strong> show a read-only copy of one result. What was scanned is hidden unless you choose to include it. Links expire (30 days by default) and you can withdraw them at any time.</li>
          <li><strong>Family and team groups</strong> show members’ names and email addresses to each other. Owners and admins see how many warnings a member had in the last 30 days only if that member turns it on, and never which sites, messages or files.</li>
          <li><strong>Telegram, WhatsApp and scan-by-email</strong> work without an account. Your chat ID, phone number or email address is kept only until the reply is sent. Messages pass through Telegram, Meta or the operator’s mail provider under their own privacy terms.</li>
          <li><strong>Breach checks</strong> send your own account email address to Have I Been Pwned. Password checks never leave your browser except for the first five characters of the password’s SHA-1 fingerprint.</li>
          <li><strong>Webhooks</strong> send your own scan results to the address you set up.</li>
          <li><strong>Browser notifications</strong> go through your browser maker’s push service (for example Google or Mozilla). They contain only a title, a sentence and a link back to SENTINEL, never what you scanned.</li>
          <li><strong>The weekly summary</strong> and <strong>breach monitoring</strong> are off until you turn them on in settings.</li>
          <li><strong>The public trends page</strong> shows only totals across everyone, and hides anything seen fewer than three times.</li>
        </ul>
      </section>
      <section>
        <h2>Your controls</h2>
        <p>
          In your account settings you can stop saving scans to your history, export everything
          stored about you as JSON, delete individual scans or your whole history, and delete your
          account. Deleting your account removes your scans and activity log immediately.
        </p>
      </section>
      <section>
        <h2>What we do not do</h2>
        <p>
          No advertising, no analytics or tracking scripts, no selling or sharing of data. The site
          loads its fonts and scripts from this server only.
        </p>
      </section>
    </ProsePage>
  );
}

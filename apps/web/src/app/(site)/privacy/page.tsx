import type { Metadata } from "next";

import Link from "next/link";

import { ProsePage } from "@/components/site/prose";

export const metadata: Metadata = { title: "Privacy" };

export default function PrivacyPage() {
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
          <li>If the operator has configured a live URLhaus key, the link is also sent to abuse.ch. The <Link href="/#integrations">integrations list</Link> shows whether that is the case.</li>
        </ul>
        <p>Uploaded files are never sent to any third party.</p>
      </section>
      <section>
        <h2>The browser extension</h2>
        <ul>
          <li>For each page you open, SENTINEL Protect sends its address (or, in privacy mode, only the domain) to the SENTINEL server. The server answers from its local threat database and stores nothing about the request.</li>
          <li>It never sends page content, form contents, passwords or messages. Private-network and local addresses are not sent at all.</li>
          <li>Recent alerts, your lists and settings are stored only in your browser.</li>
          <li>If you link it to an account and turn on warning history, the domain, the verdict and what you chose are saved to your account. You can delete that history at any time.</li>
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

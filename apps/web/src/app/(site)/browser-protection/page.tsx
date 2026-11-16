import type { Metadata } from "next";

import { ProsePage } from "@/components/site/prose";

export const metadata: Metadata = { title: "Browser protection" };

export default function BrowserProtectionPage() {
  return (
    <ProsePage
      title="SENTINEL Protect"
      intro="A browser extension that brings SENTINEL's link checks into everyday browsing. It is in development and not yet available to install."
    >
      <section>
        <h2>What it is being built to do</h2>
        <ul>
          <li>Check each site you visit against the same threat intelligence the link scanner uses, with caching so browsing stays fast.</li>
          <li>Show a clear warning page before a destination that is known to be dangerous, with the specific reason and a way back.</li>
          <li>Add a “Scan with SENTINEL” option to the right-click menu for links.</li>
          <li>Check the reputation of files you download, where the browser allows it.</li>
          <li>Show what it checked and when, and say plainly when a check could not run.</li>
        </ul>
      </section>
      <section>
        <h2>What it will not do</h2>
        <ul>
          <li>Read your passwords, form contents, card details or private messages.</li>
          <li>Send the content of the pages you visit to SENTINEL.</li>
          <li>Warn about every unfamiliar site. Warnings are reserved for meaningful evidence.</li>
          <li>Replace the antivirus protection on your device, or claim to block every harmful file.</li>
        </ul>
      </section>
      <section>
        <h2>Until then</h2>
        <p>
          Paste any link you are unsure about into the <a href="/scan?type=url">link scanner</a>.
          It runs the same checks the extension will.
        </p>
      </section>
    </ProsePage>
  );
}

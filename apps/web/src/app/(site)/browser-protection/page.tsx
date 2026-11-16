import type { Metadata } from "next";

import Link from "next/link";

import { ProsePage } from "@/components/site/prose";

export const metadata: Metadata = { title: "Browser protection" };

export default function BrowserProtectionPage() {
  return (
    <ProsePage
      title="SENTINEL Protect"
      intro="A free browser extension that checks the sites you open and warns you before a known dangerous page loads. It works with or without a SENTINEL account."
    >
      <section>
        <h2>What it does</h2>
        <ul>
          <li>Checks each site you open against SENTINEL’s threat database and look-alike detection, with caching so browsing stays fast.</li>
          <li>Shows a warning page before known dangerous sites and convincing imitations, with the specific reason and a clear way back.</li>
          <li>Adds “Scan link with SENTINEL” to the right-click menu.</li>
          <li>Pauses downloads from known dangerous sources, or with disguised names such as <code>invoice.pdf.exe</code>, and asks what you want to do.</li>
          <li>Can check links when you hover over them, if you turn that on.</li>
          <li>Shows the status of the current site, when it was checked, and plainly says when a check could not run.</li>
        </ul>
      </section>
      <section>
        <h2>Installing it</h2>
        <p>
          SENTINEL Protect is not yet published in the Chrome Web Store. To install it in Chrome or
          Microsoft Edge, build it from the project source:
        </p>
        <ul>
          <li>In <code>apps/extension</code>, run <code>npm install</code> and then <code>npm run build</code>, setting <code>SENTINEL_SERVER</code> to this site’s address.</li>
          <li>Open <code>chrome://extensions</code> (or <code>edge://extensions</code>), turn on Developer mode, choose “Load unpacked” and select <code>apps/extension/dist/chrome</code>.</li>
          <li>To see it in your dashboard, create a link code under <Link href="/dashboard/browser-protection">Browser protection</Link> and enter it in the extension’s settings.</li>
        </ul>
      </section>
      <section>
        <h2>What it does not do</h2>
        <ul>
          <li>Read your passwords, form contents, card details or private messages.</li>
          <li>Send the content of the pages you visit to SENTINEL.</li>
          <li>Warn about every unfamiliar site. Warnings are reserved for meaningful evidence.</li>
          <li>Replace the antivirus protection on your device, or claim to block every harmful file.</li>
          <li>Record the sites you visit. Checks are answered and forgotten; a linked account keeps warnings only if you turn that on, and then only the domain.</li>
        </ul>
      </section>
      <section>
        <h2>Limits</h2>
        <p>
          Browsers do not let extensions pause a page before it starts loading, so a dangerous page
          may begin to load for a moment before the warning replaces it. The extension cannot read
          downloaded files, only where they come from and what they are called. For a deeper
          check of any link, use the <Link href="/scan?type=url">link scanner</Link>.
        </p>
      </section>
    </ProsePage>
  );
}

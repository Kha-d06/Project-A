import type { Metadata } from "next";

import { ProsePage } from "@/components/site/prose";

export const metadata: Metadata = { title: "Terms" };

export default function TermsPage() {
  return (
    <ProsePage title="Terms of use" intro="Short, because the service is simple and free.">
      <section>
        <h2>What the service is</h2>
        <p>
          SENTINEL gives an opinion about links, messages and files based on the checks described in
          each report. It is provided free of charge and as is. A result of “no known threat
          detected” is not a promise that something is safe, and SENTINEL does not replace the
          security software on your device.
        </p>
      </section>
      <section>
        <h2>Fair use</h2>
        <ul>
          <li>Only submit content you are entitled to share. Do not upload other people’s private files.</li>
          <li>Do not use SENTINEL to probe or attack other systems, or to work around its rate limits.</li>
          <li>Do not attempt to break into accounts or the service itself. Report security problems to the operator instead.</li>
        </ul>
      </section>
      <section>
        <h2>Accounts</h2>
        <p>
          You are responsible for keeping your password private. You can delete your account at any
          time from its settings.
        </p>
      </section>
    </ProsePage>
  );
}

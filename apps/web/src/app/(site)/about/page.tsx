import type { Metadata } from "next";

import { ProsePage } from "@/components/site/prose";

export const metadata: Metadata = { title: "About" };

const contactUrl = process.env.NEXT_PUBLIC_CONTACT_URL;

export default function AboutPage() {
  return (
    <ProsePage
      title="About Qalaa"
      intro="Qalaa is a free, open project that helps people judge whether a link, message or file can be trusted, and explains the evidence in plain language."
    >
      <section>
        <h2>Why it exists</h2>
        <p>
          Most scams succeed not because people are careless, but because a convincing message
          arrives at a busy moment. A second opinion that is quick, understandable and honest about
          its limits can be enough to make someone pause.
        </p>
      </section>
      <section id="principles">
        <h2>Principles</h2>
        <ul>
          <li><strong>Free for everyone.</strong> There are no paid plans and no locked features.</li>
          <li><strong>Evidence over alarm.</strong> Every verdict lists the findings and checks behind it.</li>
          <li><strong>Never “safe”.</strong> The best result is “no known threat detected”, because that is all any scanner can honestly say.</li>
          <li><strong>Minimal data.</strong> Items are checked on our server and discarded; accounts are optional.</li>
        </ul>
      </section>
      <section id="limits">
        <h2>Detection limits</h2>
        <p>
          Threat feeds only contain what has been reported, so new attacks can pass reputation
          checks. File analysis is static: files are inspected but never run, so behaviour that only
          appears at runtime is not seen. Message analysis recognises common scam wording in English
          and Arabic and can miss unusual scams. Each report lists the limits that applied to it.
        </p>
      </section>
      <section id="roadmap">
        <h2>What is next</h2>
        <ul>
          <li>Community reports of scams, with moderation, and a full Arabic interface.</li>
          <li>A threat-intelligence lookup page and an administration area.</li>
          <li>Mobile-friendly sharing to Qalaa from your phone.</li>
        </ul>
      </section>
      <section id="contact">
        <h2>Contact</h2>
        {contactUrl ? (
          <p>
            Questions, false positives and security reports: <a href={contactUrl}>{contactUrl}</a>
          </p>
        ) : (
          <p>
            The operator of this Qalaa deployment has not published a contact address. If you
            run this instance, set <code className="font-mono text-ink">NEXT_PUBLIC_CONTACT_URL</code>.
          </p>
        )}
      </section>
    </ProsePage>
  );
}

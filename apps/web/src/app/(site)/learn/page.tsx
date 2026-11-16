import type { Metadata } from "next";
import Link from "next/link";

import { ARTICLES, articleText } from "@/content/awareness";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = {
  title: "Learn to spot scams",
  description: "Short guides to the scams going around right now, and what to do about them.",
};

export default async function LearnPage() {
  const locale = await getLocale();
  const t = getDictionary(locale).extra.learn;
  return (
    <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
      <header className="mb-10 max-w-2xl space-y-3">
        <h1 className="font-display text-display font-bold text-ink">{t.title}</h1>
        <p className="text-lg text-ink-muted">{t.description}</p>
      </header>
      <ul className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {ARTICLES.map((article) => {
          const text = articleText(article, locale);
          return (
            <li key={article.slug}>
              <Link
                href={`/learn/${article.slug}`}
                className="flex h-full flex-col gap-3 rounded-panel border border-line bg-surface p-5 transition-colors hover:border-accent"
              >
                <h2 className="font-display text-lg font-semibold text-ink">{text.title}</h2>
                <p className="flex-1 text-sm text-ink-muted">{text.summary}</p>
                <span className="text-sm font-medium text-accent">{t.readMore} →</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

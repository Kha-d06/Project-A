import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { ButtonLink } from "@/components/ui/button";
import { ARTICLES, articleText } from "@/content/awareness";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export function generateStaticParams() {
  return ARTICLES.map((article) => ({ slug: article.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params;
  const article = ARTICLES.find((item) => item.slug === slug);
  return article ? { title: article.en.title, description: article.en.summary } : {};
}

export default async function ArticlePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const article = ARTICLES.find((item) => item.slug === slug);
  if (!article) notFound();
  const locale = await getLocale();
  const t = getDictionary(locale).extra.learn;
  const text = articleText(article, locale);
  return (
    <article className="mx-auto max-w-3xl space-y-8 px-4 py-12 sm:px-6">
      <Link href="/learn" className="text-sm text-ink-muted hover:text-ink">
        ← {t.back}
      </Link>
      <header className="space-y-3">
        <h1 className="font-display text-title font-bold text-ink sm:text-display">{text.title}</h1>
        <p className="text-lg text-ink-muted">{text.summary}</p>
      </header>
      <p className="leading-relaxed text-ink">{text.body}</p>
      <section className="space-y-3 rounded-panel border border-warning/40 bg-warning-soft p-5">
        <h2 className="font-display text-lg font-semibold text-ink">{t.signs}</h2>
        <ul className="list-disc space-y-1.5 ps-5 text-ink">
          {text.signs.map((sign) => (
            <li key={sign}>{sign}</li>
          ))}
        </ul>
      </section>
      <section className="space-y-3 rounded-panel border border-line bg-surface p-5">
        <h2 className="font-display text-lg font-semibold text-ink">{t.whatToDo}</h2>
        <ol className="list-decimal space-y-1.5 ps-5 text-ink">
          {text.steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </section>
      <ButtonLink href={`/scan?type=${article.scanType}`}>{t.checkIt}</ButtonLink>
    </article>
  );
}

---
name: qalaa-seo-geo
description: Technical SEO and GEO (AI answer-engine) rules for Qalaa's public website, docs and comparison pages in apps/web. Load when adding or changing public routes, metadata, robots, sitemap, llms.txt, JSON-LD, Open Graph, hreflang or page performance.
---

# Qalaa SEO and GEO

## Rendering and crawlability
- Public pages live in `apps/web/src/app/(site)` and must render their full
  content on the server (no client-only shells, no content hidden until JS
  runs). Private routes (`/dashboard`, auth, `/api`, `/share`) are noindex and
  disallowed in robots.
- Use Next's file conventions (`app/robots.ts`, `app/sitemap.ts`, metadata
  `alternates.canonical` and `alternates.languages`). Read
  `node_modules/next/dist/docs` before using them: this Next version differs
  from training data.
- `/llms.txt` and `/llms-full.txt` at the root: plain Markdown describing what
  Qalaa does, platform support and limits, with links to docs. Facts only.
- robots: allow Googlebot, Bingbot, OAI-SearchBot, ClaudeBot, PerplexityBot on
  public routes.

## Structured data (JSON-LD, validated)
`Organization` and `BreadcrumbList` sitewide; `SoftwareApplication`
(operatingSystem Windows, macOS, Linux, Android; price 0) on product and
download pages; `FAQPage` only where the FAQ is visible on the page;
`HowTo`/`TechArticle` on setup guides. Never mark up content that isn't shown.

## Content
- Open each feature or comparison page with a direct 1-2 sentence answer.
- Comparison pages (`/compare/...`) are honest: a real feature table, what
  Qalaa does not do, and dated facts. No invented benchmarks or competitor
  claims; cite sources.
- English and Arabic with `hreflang` pairs and `x-default`; Arabic is RTL.
- Calm design from the redesign: shadcn/ui primitives only where accessibility
  needs them; no Magic UI, no decorative motion.

## Performance and headers
LCP < 2.5 s, INP < 200 ms, CLS < 0.1: explicit media sizes, self-hosted WOFF2
fonts with swap, no layout-shifting banners. Keep HSTS, CSP, nosniff and
Referrer-Policy.

## Tests
Playwright checks per public route: status 200, canonical present, hreflang
pair, JSON-LD parses and matches the visible content, robots and sitemap
contents; axe audit in both languages and themes (already in CI).

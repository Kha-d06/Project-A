"use client";

import { useEffect, useState } from "react";

import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api/client";
import type { Trends } from "@/lib/api/types";
import { useI18n } from "@/lib/i18n/client";

const TECHNIQUES: Record<string, [string, string]> = {
  credential_request: ["Requests for codes or passwords", "طلب رموز أو كلمات مرور"],
  account_threat: ["Threats to suspend an account", "التهديد بإيقاف حساب"],
  delivery_scam: ["Fake delivery fees", "رسوم توصيل مزيفة"],
  fine_scam: ["Fake fines and penalties", "مخالفات وغرامات مزيفة"],
  government_impersonation: ["Fake government messages", "رسائل حكومية مزيفة"],
  prize_scam: ["Prize and lottery scams", "احتيال الجوائز واليانصيب"],
  job_scam: ["Fake job offers", "عروض عمل مزيفة"],
  investment_scam: ["Investment and crypto scams", "احتيال الاستثمار والعملات الرقمية"],
  payment_pressure: ["Pressure to pay", "الضغط للدفع"],
  pilgrimage_scam: ["Fake Hajj and Umrah offers", "عروض حج وعمرة مزيفة"],
  utility_scam: ["Utility cut-off threats", "التهديد بقطع الخدمات"],
  personal_data_request: ["Requests for personal data", "طلب بيانات شخصية"],
  brand_impersonation: ["Brand names in fake addresses", "أسماء علامات في عناوين مزيفة"],
  typosquatting: ["Look-alike domains", "نطاقات مقلِّدة"],
  homograph: ["Look-alike characters", "حروف متشابهة"],
  visual_impersonation: ["Copied sign-in pages", "صفحات دخول منسوخة"],
  macros: ["Documents with macros", "مستندات بوحدات ماكرو"],
  disguised_file: ["Programs disguised as documents", "برامج متنكرة كمستندات"],
  known_signature: ["Known malware signatures", "توقيعات برمجيات ضارة معروفة"],
  threat_intelligence: ["Listed in threat feeds", "مدرج في مصادر التهديدات"],
  community_report: ["Reported by the community", "أبلغ عنه المجتمع"],
  personal_number_sender: ["Official-looking texts from personal numbers", "رسائل رسمية من أرقام شخصية"],
};

function Bars({ data, label }: { data: Record<string, number>; label: (key: string) => string }) {
  const { t } = useI18n();
  const entries = Object.entries(data);
  if (!entries.length) return <p className="px-5 py-4 text-sm text-ink-muted">{t.extra.trends.empty}</p>;
  const max = Math.max(...entries.map(([, value]) => value));
  return (
    <ul className="space-y-3 px-5 py-4">
      {entries.map(([key, value]) => (
        <li key={key} className="space-y-1">
          <div className="flex justify-between gap-3 text-sm">
            <span className="text-ink">{label(key)}</span>
            <span className="tabular-nums text-ink-muted">{value.toLocaleString()}</span>
          </div>
          <div className="h-2 rounded-full bg-surface-sunken" aria-hidden>
            <div className="h-2 rounded-full bg-accent" style={{ width: `${Math.max(4, (value / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export function TrendsView() {
  const { t, locale } = useI18n();
  const tr = t.extra.trends;
  const [days, setDays] = useState(30);
  const [data, setData] = useState<Trends | null>(null);

  useEffect(() => {
    api.trends(days).then(setData, () => setData(null));
  }, [days]);

  const ar = locale === "ar";
  return (
    <div className="mx-auto max-w-6xl space-y-8 px-4 py-12 sm:px-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-2xl space-y-2">
          <h1 className="font-display text-display font-bold text-ink">{tr.title}</h1>
          <p className="text-lg text-ink-muted">{tr.description}</p>
        </div>
        <div className="flex gap-1 rounded-control border border-line p-1" role="group">
          {[7, 30, 90].map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={days === value}
              onClick={() => setDays(value)}
              className="rounded-control px-3 py-1.5 text-sm text-ink-muted aria-pressed:bg-surface-sunken aria-pressed:text-ink"
            >
              {tr.period(value)}
            </button>
          ))}
        </div>
      </header>
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel>
          <PanelHeader title={tr.techniques} />
          <Bars data={data?.techniques ?? {}} label={(key) => TECHNIQUES[key]?.[ar ? 1 : 0] ?? key} />
        </Panel>
        <div className="space-y-6">
          <Panel>
            <PanelHeader title={tr.verdicts} />
            <Bars data={(data?.verdicts ?? {}) as Record<string, number>} label={(key) => t.risk[key as keyof typeof t.risk]?.label ?? key} />
          </Panel>
          <Panel>
            <PanelHeader title={tr.reports} />
            <Bars
              data={data?.verified_reports_by_category ?? {}}
              label={(key) => t.community.categories[key as keyof typeof t.community.categories]?.label ?? key}
            />
          </Panel>
          <Panel>
            <PanelHeader title={tr.countries} />
            <Bars data={data?.verified_reports_by_country ?? {}} label={(key) => key} />
          </Panel>
        </div>
      </div>
    </div>
  );
}

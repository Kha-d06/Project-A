"use client";

import { BrokerChecklist } from "@/components/dashboard/broker-checklist";
import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { EmailAliases } from "@/components/dashboard/email-aliases";
import { useI18n } from "@/lib/i18n/client";

export function PrivacyTools() {
  const { t } = useI18n();
  return (
    <>
      <PageTitle title={t.extra.privacy.title} description={t.extra.privacy.description} />
      <div className="space-y-6">
        <EmailAliases />
        <BrokerChecklist />
      </div>
    </>
  );
}

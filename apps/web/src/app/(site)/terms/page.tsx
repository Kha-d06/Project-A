import type { Metadata } from "next";

import { ProsePage } from "@/components/site/prose";
import { getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Terms" };

function TermsArabic() {
  return (
    <ProsePage language="ar" title="شروط الاستخدام" intro="مختصرة، لأن الخدمة بسيطة ومجانية.">
      <section>
        <h2>ما هي الخدمة</h2>
        <p>
          يقدّم قلعة رأيًا حول الروابط والرسائل والملفات بناءً على الفحوصات الموضحة في كل
          تقرير. الخدمة مجانية وتُقدَّم كما هي. نتيجة «لا يوجد تهديد معروف» ليست وعدًا بأن الشيء
          آمن، ولا يغني قلعة عن برامج الحماية على جهازك.
        </p>
      </section>
      <section>
        <h2>الاستخدام العادل</h2>
        <ul>
          <li>لا ترسل إلا محتوى يحق لك مشاركته، ولا ترفع ملفات خاصة بالآخرين.</li>
          <li>لا تستخدم قلعة لفحص أنظمة أخرى أو مهاجمتها، أو للتحايل على حدود الاستخدام.</li>
          <li>لا تحاول اختراق الحسابات أو الخدمة نفسها، وأبلغ المشغّل عن المشكلات الأمنية بدلًا من ذلك.</li>
        </ul>
      </section>
      <section>
        <h2>الحسابات</h2>
        <p>أنت مسؤول عن الحفاظ على سرية كلمة مرورك، ويمكنك حذف حسابك في أي وقت من إعداداته.</p>
      </section>
    </ProsePage>
  );
}

export default async function TermsPage() {
  if ((await getLocale()) === "ar") return <TermsArabic />;
  return (
    <ProsePage title="Terms of use" intro="Short, because the service is simple and free.">
      <section>
        <h2>What the service is</h2>
        <p>
          Qalaa gives an opinion about links, messages and files based on the checks described in
          each report. It is provided free of charge and as is. A result of “no known threat
          detected” is not a promise that something is safe, and Qalaa does not replace the
          security software on your device.
        </p>
      </section>
      <section>
        <h2>Fair use</h2>
        <ul>
          <li>Only submit content you are entitled to share. Do not upload other people’s private files.</li>
          <li>Do not use Qalaa to probe or attack other systems, or to work around its rate limits.</li>
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

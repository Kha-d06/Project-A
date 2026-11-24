/** English and Arabic text for the add-on's pages. */
const en = {
  checking: "Checking this email…",
  notChecked: "This email has not been checked.",
  setup: "Set the Qalaa server in the add-on's options first.",
  failed: (why) => `The check could not be completed: ${why}`,
  risk: {
    known_malicious: "Known malicious",
    suspicious: "Warning signs",
    no_known_threat: "No known threat",
    inconclusive: "Not enough to tell",
  },
  limitsTitle: "What this check could not see",
  privacy: "This email was checked on this computer. Only its links, without query strings, were sent to your Qalaa server for a reputation check, which keeps nothing.",
  rulesUnavailable: "The scam-wording rules could not be downloaded, so only the sender, header and link checks ran.",
  linksUnchecked: "The links could not be checked against the threat lists this time.",
  serverLabel: "Qalaa server address",
  save: "Save and allow",
  saved: "Saved. Emails you open will be checked.",
  denied: "Thunderbird did not allow access to that server, so emails cannot be checked.",
  autoCheck: "Check every email when it is opened",
  optionsIntro: "Qalaa checks the email you open for forged senders, look-alike links and pressure tactics. Nothing is checked until you save a server here.",
};

const ar = {
  checking: "جارٍ فحص هذه الرسالة…",
  notChecked: "لم تُفحص هذه الرسالة.",
  setup: "حدد خادم قلعة في خيارات الإضافة أولًا.",
  failed: (why) => `تعذر إكمال الفحص: ${why}`,
  risk: {
    known_malicious: "خبيثة معروفة",
    suspicious: "علامات تحذير",
    no_known_threat: "لا تهديد معروف",
    inconclusive: "لا يكفي للحكم",
  },
  limitsTitle: "ما لم يستطع هذا الفحص رؤيته",
  privacy: "فُحصت هذه الرسالة على هذا الحاسوب. أُرسلت روابطها فقط، دون معاملات الاستعلام، إلى خادم قلعة لفحص سمعتها، ولا يحتفظ الخادم بشيء.",
  rulesUnavailable: "تعذر تنزيل قواعد عبارات الاحتيال، لذا جرى فحص المرسل والترويسات والروابط فقط.",
  linksUnchecked: "تعذر فحص الروابط مقابل قوائم التهديدات هذه المرة.",
  serverLabel: "عنوان خادم قلعة",
  save: "احفظ واسمح",
  saved: "حُفظ. ستُفحص الرسائل التي تفتحها.",
  denied: "لم يسمح Thunderbird بالوصول إلى ذلك الخادم، لذا لا يمكن فحص الرسائل.",
  autoCheck: "افحص كل رسالة عند فتحها",
  optionsIntro: "يفحص قلعة الرسالة التي تفتحها بحثًا عن المرسلين المزيفين والروابط المقلّدة وأساليب الضغط. لا يُفحص شيء حتى تحفظ خادمًا هنا.",
};

export function language() {
  const ui = globalThis.messenger?.i18n?.getUILanguage?.() ?? globalThis.navigator?.language ?? "en";
  return String(ui).toLowerCase().startsWith("ar") ? "ar" : "en";
}

export function t() {
  return language() === "ar" ? ar : en;
}

export function localizePage() {
  const lang = language();
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  const dict = t();
  for (const element of document.querySelectorAll("[data-i18n]")) {
    const value = dict[element.dataset.i18n];
    if (typeof value === "string") element.textContent = value;
  }
}

export const dictionaries = { en, ar };

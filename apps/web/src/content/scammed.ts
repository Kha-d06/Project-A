/**
 * "I think I've been scammed": urgent steps by situation, in order of priority.
 * General guidance only; it points people to their bank and the police rather
 * than replacing them.
 */
export interface Situation {
  id: string;
  en: { title: string; steps: string[] };
  ar: { title: string; steps: string[] };
}

export const SITUATIONS: Situation[] = [
  {
    id: "card",
    en: {
      title: "I entered my card details or paid by card",
      steps: [
        "Call your bank now on the number printed on the back of your card, and ask them to block the card.",
        "In your banking app, freeze the card if that option exists, while you wait to get through.",
        "Ask the bank to dispute (charge back) the payment. Card payments can often be reversed if you act quickly.",
        "Check recent transactions for small test payments you do not recognise.",
        "Be careful of follow-up calls offering to \"recover\" your money: that is a second scam.",
      ],
    },
    ar: {
      title: "أدخلت بيانات بطاقتي أو دفعت بالبطاقة",
      steps: [
        "اتصل ببنكك الآن على الرقم المطبوع خلف البطاقة واطلب إيقافها.",
        "جمّد البطاقة من تطبيق البنك إن توفر هذا الخيار، ريثما يُرد على اتصالك.",
        "اطلب من البنك الاعتراض على العملية (استرداد المبلغ)؛ يمكن غالبًا عكس مدفوعات البطاقة إذا تصرفت بسرعة.",
        "راجع العمليات الأخيرة بحثًا عن دفعات صغيرة تجريبية لا تعرفها.",
        "احذر من مكالمات لاحقة تعرض «استرداد» أموالك؛ فهذه عملية احتيال ثانية.",
      ],
    },
  },
  {
    id: "transfer",
    en: {
      title: "I sent money by bank transfer or exchange",
      steps: [
        "Call your bank immediately and tell them it was a fraudulent transfer. Ask them to contact the receiving bank to freeze the money.",
        "Write down the amount, time, receiving account and any reference: the bank and the police will need them.",
        "Report it to the police or the national cybercrime service the same day.",
        "Keep the messages and call logs; do not delete the conversation with the scammer.",
      ],
    },
    ar: {
      title: "أرسلت مالًا بتحويل بنكي أو عبر صرافة",
      steps: [
        "اتصل ببنكك فورًا وأبلغه أن التحويل احتيالي، واطلب منه التواصل مع البنك المستقبِل لتجميد المبلغ.",
        "دوّن المبلغ والوقت والحساب المستقبِل وأي رقم مرجعي؛ سيحتاجها البنك والشرطة.",
        "أبلغ الشرطة أو جهة مكافحة الجرائم الإلكترونية في اليوم نفسه.",
        "احتفظ بالرسائل وسجل المكالمات، ولا تحذف المحادثة مع المحتال.",
      ],
    },
  },
  {
    id: "code",
    en: {
      title: "I shared a verification code (OTP)",
      steps: [
        "Assume the account the code protects has been taken over. Call the bank or service now if it was a banking code.",
        "For WhatsApp: open WhatsApp, register your number again to sign the other device out, then turn on two-step verification.",
        "For email or social media: change the password, sign out all other sessions, and turn on two-step verification.",
        "Warn your contacts: scammers use taken-over accounts to ask friends for money and codes.",
      ],
    },
    ar: {
      title: "شاركت رمز تحقق (OTP)",
      steps: [
        "افترض أن الحساب الذي يحميه الرمز قد سُرق. اتصل بالبنك أو الخدمة الآن إن كان رمزًا مصرفيًا.",
        "لواتساب: افتح واتساب وسجّل رقمك من جديد لإخراج الجهاز الآخر، ثم فعّل التحقق بخطوتين.",
        "للبريد أو وسائل التواصل: غيّر كلمة المرور، وسجّل الخروج من كل الجلسات الأخرى، وفعّل التحقق بخطوتين.",
        "حذّر جهات اتصالك؛ يستخدم المحتالون الحسابات المسروقة لطلب المال والرموز من الأصدقاء.",
      ],
    },
  },
  {
    id: "password",
    en: {
      title: "I typed my password on a fake page",
      steps: [
        "Change that password now on the real site (type the address yourself), and anywhere else you used the same password.",
        "Sign out of all other sessions and turn on two-step verification.",
        "Check the account's recovery email and phone number have not been changed.",
        "If it was your email account, check its forwarding rules: attackers add rules to copy your mail.",
      ],
    },
    ar: {
      title: "كتبت كلمة المرور في صفحة مزيفة",
      steps: [
        "غيّر كلمة المرور الآن في الموقع الحقيقي (اكتب العنوان بنفسك)، وفي أي مكان آخر استخدمت فيه الكلمة نفسها.",
        "سجّل الخروج من كل الجلسات الأخرى وفعّل التحقق بخطوتين.",
        "تأكد أن بريد الاسترداد ورقم الهاتف في الحساب لم يتغيرا.",
        "إن كان حساب بريدك، فراجع قواعد إعادة التوجيه؛ يضيف المهاجمون قواعد لنسخ رسائلك.",
      ],
    },
  },
  {
    id: "app",
    en: {
      title: "I installed an app or gave someone remote access",
      steps: [
        "Disconnect the device from the internet (turn on airplane mode).",
        "Uninstall the app or remote-access tool (AnyDesk, TeamViewer, an unknown APK). On Android, also remove it from accessibility and device-administrator settings.",
        "From a different, trusted device, change your banking and email passwords and call your bank.",
        "Scan the device with up-to-date security software, and consider a factory reset if banking apps were on it.",
      ],
    },
    ar: {
      title: "ثبّتُّ تطبيقًا أو منحت شخصًا تحكمًا عن بُعد",
      steps: [
        "افصل الجهاز عن الإنترنت (فعّل وضع الطيران).",
        "احذف التطبيق أو أداة التحكم عن بُعد (AnyDesk أو TeamViewer أو ملف APK مجهول). على أندرويد احذفه أيضًا من إعدادات إمكانية الوصول ومسؤول الجهاز.",
        "من جهاز آخر موثوق، غيّر كلمات مرور البنك والبريد واتصل ببنكك.",
        "افحص الجهاز ببرنامج حماية محدَّث، وفكّر في إعادة ضبط المصنع إن كانت عليه تطبيقات بنكية.",
      ],
    },
  },
  {
    id: "identity",
    en: {
      title: "I sent my ID, passport or personal details",
      steps: [
        "Tell your bank so they can watch for accounts or loans opened in your name.",
        "Report the loss of the document details to the police, and keep the report number.",
        "Be extra careful with calls and messages that quote your details back to you: that is how follow-up scams sound convincing.",
      ],
    },
    ar: {
      title: "أرسلت هويتي أو جوازي أو بياناتي الشخصية",
      steps: [
        "أبلغ بنكك ليراقب أي حسابات أو قروض تُفتح باسمك.",
        "أبلغ الشرطة عن تسرّب بيانات الوثيقة واحتفظ برقم البلاغ.",
        "كن حذرًا جدًا من المكالمات والرسائل التي تذكر بياناتك؛ فهكذا تبدو عمليات الاحتيال اللاحقة مقنعة.",
      ],
    },
  },
];

export interface Contact {
  country: { en: string; ar: string };
  items: { en: string; ar: string; href?: string }[];
}

export const CONTACTS: Contact[] = [
  {
    country: { en: "United Arab Emirates", ar: "الإمارات" },
    items: [
      { en: "eCrime reporting platform (Dubai Police)", ar: "منصة الإبلاغ عن الجرائم الإلكترونية (شرطة دبي)", href: "https://www.ecrime.ae" },
      { en: "Aman service, Abu Dhabi Police: 8002626", ar: "خدمة أمان، شرطة أبوظبي: \u20668002626\u2069" },
    ],
  },
  {
    country: { en: "Saudi Arabia", ar: "السعودية" },
    items: [{ en: "Kollona Amn app (report cybercrime)", ar: "تطبيق كلنا أمن (للإبلاغ عن الجرائم الإلكترونية)" }],
  },
  {
    country: { en: "United Kingdom", ar: "المملكة المتحدة" },
    items: [{ en: "Action Fraud: 0300 123 2040", ar: "Action Fraud: \u20660300 123 2040\u2069", href: "https://www.actionfraud.police.uk" }],
  },
  {
    country: { en: "United States", ar: "الولايات المتحدة" },
    items: [
      { en: "FTC fraud reports", ar: "بلاغات الاحتيال لدى FTC", href: "https://reportfraud.ftc.gov" },
      { en: "FBI Internet Crime Complaint Center", ar: "مركز شكاوى جرائم الإنترنت (FBI)", href: "https://www.ic3.gov" },
    ],
  },
  {
    country: { en: "Everywhere", ar: "في كل مكان" },
    items: [
      { en: "Your bank: the number on the back of your card or in its official app", ar: "بنكك: الرقم خلف البطاقة أو في تطبيقه الرسمي" },
      { en: "Your local police", ar: "الشرطة المحلية" },
    ],
  },
];

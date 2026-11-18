/** Awareness hub: short, practical guides to scams that are common right now. */
import type { Locale } from "@/lib/i18n/locales";

interface Text {
  title: string;
  summary: string;
  body: string;
  signs: string[];
  steps: string[];
}

export interface Article {
  slug: string;
  updated: string;
  scanType: "url" | "message" | "file" | "qr" | "apk";
  en: Text;
  ar: Text;
}

export const ARTICLES: Article[] = [
  {
    slug: "fake-fines-and-government-messages",
    updated: "2026-11-01",
    scanType: "message",
    en: {
      title: "Fake traffic fines and government messages",
      summary: "Texts claiming to be from the police, Absher, UAE Pass or a ministry, with a link to pay a fine or update your details.",
      body: "These messages copy the names and logos of real government services and create urgency: a fine that doubles tomorrow, a licence that will be suspended, an ID that must be re-verified. The link leads to a convincing copy of the real site that collects card details or login codes.",
      signs: [
        "A link in a text message asking you to pay or update details",
        "A web address that is not the official government domain",
        "A deadline measured in hours",
        "A request for a verification code sent to your phone",
      ],
      steps: [
        "Do not tap the link. Open the official app or type the official address yourself.",
        "Check fines only in the official police or government app.",
        "Never share a one-time code, even with someone who says they are an official.",
        "If you already paid, call your bank immediately to block the card.",
      ],
    },
    ar: {
      title: "المخالفات المرورية والرسائل الحكومية المزيفة",
      summary: "رسائل تدّعي أنها من الشرطة أو أبشر أو الهوية الرقمية أو إحدى الوزارات، مع رابط لدفع مخالفة أو تحديث بياناتك.",
      body: "تنسخ هذه الرسائل أسماء الخدمات الحكومية الحقيقية وشعاراتها وتخلق شعورًا بالاستعجال: مخالفة تتضاعف غدًا، أو رخصة ستُعلَّق، أو هوية يجب توثيقها من جديد. يقود الرابط إلى نسخة مقنعة من الموقع الحقيقي تجمع بيانات البطاقة أو رموز الدخول.",
      signs: [
        "رابط في رسالة نصية يطلب منك الدفع أو تحديث البيانات",
        "عنوان موقع ليس النطاق الحكومي الرسمي",
        "مهلة تُقاس بالساعات",
        "طلب رمز تحقق وصل إلى هاتفك",
      ],
      steps: [
        "لا تضغط على الرابط. افتح التطبيق الرسمي أو اكتب العنوان الرسمي بنفسك.",
        "تحقق من المخالفات فقط عبر تطبيق الشرطة أو الجهة الحكومية الرسمي.",
        "لا تشارك أي رمز لمرة واحدة، حتى مع شخص يقول إنه موظف رسمي.",
        "إذا دفعت بالفعل، فاتصل بالبنك فورًا لإيقاف البطاقة.",
      ],
    },
  },
  {
    slug: "parcel-delivery-fees",
    updated: "2026-10-20",
    scanType: "url",
    en: {
      title: "Parcel “redelivery fee” texts",
      summary: "A courier says your parcel is held until you pay a small fee. The fee is tiny; the real target is your card.",
      body: "Scammers send these messages to huge lists of numbers, knowing many people are expecting a delivery. The payment page asks for full card details and then a bank verification code, which lets the criminals add your card to their own phone wallet.",
      signs: [
        "A small fee (1 to 5) to release a parcel",
        "A courier name with an unusual web address",
        "A message you did not expect, for an order you cannot place",
      ],
      steps: [
        "Track parcels only on the retailer's site or the courier's official app.",
        "Never enter a bank code to “confirm” a small payment you did not start.",
        "Check the link with Qalaa before opening it.",
      ],
    },
    ar: {
      title: "رسائل «رسوم إعادة توصيل الشحنة»",
      summary: "تقول شركة شحن إن شحنتك محتجزة حتى تدفع رسومًا صغيرة. المبلغ زهيد، والهدف الحقيقي بطاقتك.",
      body: "يرسل المحتالون هذه الرسائل إلى قوائم ضخمة من الأرقام، لأن كثيرين ينتظرون شحنة. تطلب صفحة الدفع بيانات البطاقة كاملة ثم رمز تحقق من البنك، وهذا يتيح للمجرمين إضافة بطاقتك إلى محفظة هاتفهم.",
      signs: [
        "رسوم صغيرة (من 1 إلى 5) للإفراج عن شحنة",
        "اسم شركة شحن مع عنوان موقع غير معتاد",
        "رسالة لم تتوقعها عن طلب لا تتذكره",
      ],
      steps: [
        "تتبّع الشحنات فقط عبر موقع المتجر أو التطبيق الرسمي لشركة الشحن.",
        "لا تُدخل رمز البنك لـ«تأكيد» دفعة صغيرة لم تبدأها.",
        "افحص الرابط باستخدام قلعة قبل فتحه.",
      ],
    },
  },
  {
    slug: "verification-code-theft",
    updated: "2026-11-05",
    scanType: "message",
    en: {
      title: "“Send me the code you just received”",
      summary: "Whoever has your one-time code can take over your WhatsApp, bank or email account.",
      body: "The request often comes from a friend's hacked account, or from someone posing as a bank or support agent. They trigger a login code to your phone and ask you to forward it “by mistake” or “to verify you”. With it they take over the account and use it to scam your contacts.",
      signs: [
        "Anyone asking for a code that arrived by SMS or WhatsApp",
        "A friend asking urgently for a favour by message, not by voice",
        "A support agent who contacts you first",
      ],
      steps: [
        "Never share a one-time code with anyone. No real company will ask for it.",
        "Turn on two-step verification (a PIN) in WhatsApp and your email.",
        "If you shared a code, sign out other devices and change your password now.",
      ],
    },
    ar: {
      title: "«أرسل لي الرمز الذي وصلك الآن»",
      summary: "من يحصل على رمزك لمرة واحدة يستطيع الاستيلاء على حسابك في واتساب أو البنك أو البريد.",
      body: "غالبًا يأتي الطلب من حساب صديق مخترَق، أو من شخص ينتحل صفة البنك أو الدعم الفني. يطلبون رمز دخول إلى هاتفك ثم يسألونك أن تعيد إرساله «بالخطأ» أو «للتحقق منك». به يستولون على الحساب ويستخدمونه للاحتيال على جهات اتصالك.",
      signs: [
        "أي شخص يطلب رمزًا وصلك عبر الرسائل أو واتساب",
        "صديق يطلب خدمة عاجلة بالرسائل لا بالاتصال",
        "موظف دعم يتواصل معك أولًا",
      ],
      steps: [
        "لا تشارك أي رمز لمرة واحدة مع أي شخص. لن تطلبه أي شركة حقيقية.",
        "فعّل التحقق بخطوتين (رقم سري) في واتساب وبريدك.",
        "إذا شاركت رمزًا، فسجّل الخروج من الأجهزة الأخرى وغيّر كلمة المرور الآن.",
      ],
    },
  },
  {
    slug: "job-and-task-scams",
    updated: "2026-10-12",
    scanType: "message",
    en: {
      title: "Job offers that pay you to “like” or “rate”",
      summary: "Easy online tasks with a small first payment, then a request to deposit money to unlock bigger earnings.",
      body: "The first tasks really pay a little, to build trust. Then you are moved to a Telegram or WhatsApp group and told to deposit money to complete “premium tasks”. The balance on the website grows, but it can never be withdrawn without another deposit.",
      signs: [
        "A job offer you did not apply for",
        "Pay that is far too high for simple tasks",
        "Any request to pay, deposit or buy crypto to earn",
      ],
      steps: [
        "A real employer never asks you to pay them.",
        "Stop depositing, even to “recover” what you already paid.",
        "Report the number to Qalaa and to your bank.",
      ],
    },
    ar: {
      title: "عروض عمل تدفع لك مقابل «الإعجاب» أو «التقييم»",
      summary: "مهام سهلة عبر الإنترنت مع دفعة أولى صغيرة، ثم طلب إيداع مال لفتح أرباح أكبر.",
      body: "تُدفع المهام الأولى فعلًا بمبالغ صغيرة لبناء الثقة. ثم تُنقل إلى مجموعة على تيليجرام أو واتساب ويُطلب منك إيداع مال لإكمال «مهام مميزة». يكبر رصيدك على الموقع لكن لا يمكن سحبه أبدًا دون إيداع جديد.",
      signs: [
        "عرض عمل لم تتقدم إليه",
        "أجر مرتفع جدًا مقابل مهام بسيطة",
        "أي طلب للدفع أو الإيداع أو شراء عملات رقمية لكي تربح",
      ],
      steps: [
        "صاحب العمل الحقيقي لا يطلب منك أن تدفع له.",
        "توقف عن الإيداع، حتى لـ«استرداد» ما دفعته.",
        "أبلغ قلعة والبنك عن الرقم.",
      ],
    },
  },
  {
    slug: "qr-code-scams",
    updated: "2026-09-30",
    scanType: "qr",
    en: {
      title: "QR codes on parking meters and menus",
      summary: "A sticker placed over a real QR code sends you to a fake payment page.",
      body: "Because a QR code hides its address, it is an easy way to slip a fake link into a real place: a parking machine, a restaurant table or a flyer. The page looks like a normal payment form.",
      signs: [
        "A sticker that looks added on top of the original",
        "A payment page that asks for more than the amount due",
        "An address that does not match the business",
      ],
      steps: [
        "Pay parking through the official app instead of a code.",
        "Check where a code leads with Qalaa's QR scanner before paying.",
        "Tell the business if a code looks tampered with.",
      ],
    },
    ar: {
      title: "رموز QR على عدادات المواقف وقوائم الطعام",
      summary: "ملصق يوضع فوق رمز QR الحقيقي يرسلك إلى صفحة دفع مزيفة.",
      body: "لأن رمز QR يخفي عنوانه، فهو طريقة سهلة لدسّ رابط مزيف في مكان حقيقي: جهاز مواقف أو طاولة مطعم أو منشور. تبدو الصفحة نموذج دفع عاديًا.",
      signs: [
        "ملصق يبدو مضافًا فوق الرمز الأصلي",
        "صفحة دفع تطلب أكثر من المبلغ المستحق",
        "عنوان لا يطابق اسم النشاط التجاري",
      ],
      steps: [
        "ادفع المواقف عبر التطبيق الرسمي بدل الرمز.",
        "تحقق من وجهة الرمز بماسح QR في قلعة قبل الدفع.",
        "أبلغ صاحب المكان إذا بدا الرمز معدَّلًا.",
      ],
    },
  },
  {
    slug: "hajj-umrah-offers",
    updated: "2026-11-10",
    scanType: "url",
    en: {
      title: "Cheap Hajj and Umrah packages",
      summary: "Social-media offers for guaranteed permits or visas at low prices, paid in advance.",
      body: "Fake agencies advertise heavily before each season, using photos of real hotels and copied licence numbers. Money is taken in advance by bank transfer, and the agency disappears before travel.",
      signs: [
        "A price far below licensed agencies",
        "“Guaranteed” Hajj permits outside the official system",
        "Payment by personal bank transfer only",
      ],
      steps: [
        "Book Hajj only through the official Nusuk platform or an agency it lists.",
        "Check the agency's licence with the official authority.",
        "Never pay by transfer to a personal account.",
      ],
    },
    ar: {
      title: "باقات حج وعمرة رخيصة",
      summary: "عروض على وسائل التواصل لتصاريح أو تأشيرات «مضمونة» بأسعار منخفضة تُدفع مقدمًا.",
      body: "تعلن وكالات مزيفة بكثافة قبل كل موسم، مستخدمة صور فنادق حقيقية وأرقام تراخيص منسوخة. يُؤخذ المال مقدمًا بالتحويل البنكي، ثم تختفي الوكالة قبل السفر.",
      signs: [
        "سعر أقل بكثير من الوكالات المرخصة",
        "تصاريح حج «مضمونة» خارج النظام الرسمي",
        "الدفع بتحويل إلى حساب شخصي فقط",
      ],
      steps: [
        "احجز الحج فقط عبر منصة نسك الرسمية أو وكالة مدرجة فيها.",
        "تحقق من ترخيص الوكالة لدى الجهة الرسمية.",
        "لا تدفع أبدًا بتحويل إلى حساب شخصي.",
      ],
    },
  },
  {
    slug: "investment-and-crypto",
    updated: "2026-10-01",
    scanType: "url",
    en: {
      title: "Investment and crypto “opportunities”",
      summary: "Guaranteed daily returns, celebrity endorsements and a trading app that shows profits you cannot withdraw.",
      body: "These schemes use fake news articles and deepfake videos of well-known people. A “personal manager” guides you to deposit, the dashboard shows growing profits, and every withdrawal triggers a new fee or tax.",
      signs: [
        "Guaranteed or very high returns",
        "Pressure to invest quickly",
        "A withdrawal that needs another payment first",
      ],
      steps: [
        "Check whether the firm is licensed by your country's financial regulator.",
        "Do not install remote-access apps at anyone's request.",
        "Keep records and report to your bank and the police.",
      ],
    },
    ar: {
      title: "«فرص» الاستثمار والعملات الرقمية",
      summary: "أرباح يومية مضمونة وتأييد مشاهير وتطبيق تداول يعرض أرباحًا لا يمكنك سحبها.",
      body: "تستخدم هذه المخططات أخبارًا مزيفة ومقاطع فيديو مصطنعة لأشخاص معروفين. يرشدك «مدير حساب» إلى الإيداع، وتعرض اللوحة أرباحًا متزايدة، ثم يتطلب كل سحب رسومًا أو ضريبة جديدة.",
      signs: [
        "أرباح مضمونة أو مرتفعة جدًا",
        "ضغط للاستثمار بسرعة",
        "سحب يتطلب دفعة أخرى أولًا",
      ],
      steps: [
        "تحقق من ترخيص الشركة لدى هيئة الرقابة المالية في بلدك.",
        "لا تثبّت تطبيقات التحكم عن بُعد بطلب من أحد.",
        "احتفظ بالسجلات وأبلغ البنك والشرطة.",
      ],
    },
  },
  {
    slug: "family-member-in-trouble",
    updated: "2026-10-25",
    scanType: "message",
    en: {
      title: "“Hi, it's me, I lost my phone”",
      summary: "A message from a new number claiming to be your son, daughter or parent, who urgently needs money.",
      body: "The scammer writes in a familiar tone, says their phone broke, and asks you to pay a bill or transfer money right away, often to a third person. Some now use cloned voice notes.",
      signs: [
        "A new number claiming to be someone you know",
        "An urgent money request with a reason you cannot check",
        "Excuses for why they cannot call",
      ],
      steps: [
        "Call the person on their old number, or ask a question only they would know.",
        "Agree on a family code word for real emergencies.",
        "Never transfer money because of a message alone.",
      ],
    },
    ar: {
      title: "«مرحبًا، أنا… ضاع هاتفي»",
      summary: "رسالة من رقم جديد تدّعي أنها من ابنك أو ابنتك أو أحد والديك، ويحتاج المال بشكل عاجل.",
      body: "يكتب المحتال بأسلوب مألوف ويقول إن هاتفه تعطل، ثم يطلب منك دفع فاتورة أو تحويل مال فورًا، غالبًا إلى شخص ثالث. بعضهم يستخدم الآن رسائل صوتية مستنسخة.",
      signs: [
        "رقم جديد يدّعي أنه شخص تعرفه",
        "طلب مال عاجل لسبب لا يمكنك التحقق منه",
        "أعذار لعدم قدرته على الاتصال",
      ],
      steps: [
        "اتصل بالشخص على رقمه القديم، أو اسأله سؤالًا لا يعرفه غيره.",
        "اتفقوا في العائلة على كلمة سر للطوارئ الحقيقية.",
        "لا تحوّل مالًا بناءً على رسالة فقط.",
      ],
    },
  },
];

export function articleText(article: Article, locale: Locale): Text {
  return locale === "ar" ? article.ar : article.en;
}

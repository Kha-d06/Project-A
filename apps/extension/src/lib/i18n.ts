/**
 * English and Arabic text for the extension. Pages and content scripts call
 * initLanguage() once, then read strings through t(). Static HTML marks text
 * with data-i18n="key" (or data-i18n-placeholder / data-i18n-aria-label) and
 * localizeDocument() fills it in, also setting lang and dir.
 */
import type { Verdict } from "./types";

export type Language = "en" | "ar";
export type LanguageSetting = "auto" | Language;

const en = {
  verdicts: {
    dangerous: { label: "Dangerous", detail: "This site is listed in threat intelligence as malicious." },
    suspicious: { label: "Suspicious", detail: "Strong warning signs, such as a look-alike of a well-known brand." },
    caution: { label: "Caution", detail: "Some warning signs. Be careful with passwords and payments here." },
    no_known_threat: { label: "No known threat", detail: "Checks found no known problems. That is not a guarantee of safety." },
    unavailable: { label: "Check unavailable", detail: "SENTINEL could not check this site, so it is not protected right now." },
    skipped: { label: "Not checked", detail: "Local and private-network addresses are not checked." },
    blocked_by_you: { label: "Blocked by you", detail: "This site is on your block list." },
    allowed_by_you: { label: "Not checked (allowed by you)", detail: "This site is on your allow list, so SENTINEL does not check it." },
  } satisfies Record<Verdict, { label: string; detail: string }>,
  time: {
    justNow: "just now",
    minutes: (n: number) => `${n} min ago`,
    hours: (n: number) => `${n} h ago`,
  },
  popup: {
    protection: "Protection",
    protectionToggle: "Pause or resume protection",
    protectionOn: "Protection on",
    protectionPaused: "Protection paused",
    notConnected: "Not connected",
    recentAlerts: "Recent alerts",
    clear: "Clear",
    openDashboard: "Open dashboard",
    settings: "Settings",
    checking: "Checking this page…",
    openSite: "Open a website to see its status here.",
    pausedNotChecked: "Protection is paused, so this page was not checked.",
    onlyWeb: "SENTINEL only checks web pages (http and https).",
    checked: (when: string) => `Checked ${when}`,
    fullScan: "Run a full scan",
    connect: "Connect",
    notConnectedTitle: "Not connected to a SENTINEL server",
    notConnectedBody: (server: string) => `Sites are not being checked. The server at ${server} could not be reached when the extension started.`,
    noAlerts: "No alerts. Warnings you see will be listed here.",
    preloaded: (count: number) => `${count.toLocaleString()} known dangerous sites are blocked before they load.`,
  },
  warning: {
    title: "Warning: SENTINEL blocked this page",
    loading: "Loading the details of this warning…",
    headlineDangerous: "This site is known to be dangerous",
    headlineSuspicious: "This site looks like an imitation",
    headlineBlocked: "You blocked this site",
    adviceDangerous: "Do not enter passwords, payment details or personal information, and do not download anything from it.",
    adviceSuspicious: "If you were expecting a well-known service, type its address yourself or use its official app instead.",
    adviceBlocked: "You can remove it from your block list in the extension settings.",
    riskLevel: (label: string) => `Risk level: ${label}.`,
    why: "WHY SENTINEL STOPPED THIS PAGE",
    source: (name: string) => `Source: ${name}`,
    goBack: "Go back to safety",
    understand: "I understand the risk",
    proceedDangerous: "Threat intelligence lists this address as malicious. Continuing could expose your device or accounts. SENTINEL will not warn about this site again until you restart the browser.",
    proceedSuspicious: "These are warning signs, not proof. If you are sure this is the site you meant to visit, you can continue. SENTINEL will not warn about it again until you restart the browser.",
    continueTo: (host: string) => `Continue to ${host}`,
    noAddress: "No address was given.",
    stopped: "SENTINEL stopped this page",
    back: "Go back",
    notChecked: "This address could not be checked.",
    preloadReason: "On SENTINEL's list of known malicious domains",
    preloadExplanation: "This domain is on the list of known dangerous sites that SENTINEL Protect keeps in your browser, so it was blocked before it could load.",
    preloadSource: "SENTINEL blocklist (in your browser)",
  },
  notifications: {
    downloadPaused: (label: string) => `${label} download paused`,
    cancel: "Cancel download",
    keep: "Keep it anyway",
    downloadsPanel: "Open the downloads panel to cancel or resume it.",
    notChecked: "Not checked",
    notCheckedBody: "Only web addresses (http and https) on the public internet can be checked.",
    scanLink: "Scan link with SENTINEL",
    checkPage: "Check this page with SENTINEL",
  },
  options: {
    pageTitle: "SENTINEL Protect settings",
    title: "Settings",
    protection: "Protection",
    paused: "Pause protection",
    pausedHint: "While paused, no sites are checked and no warnings appear.",
    warnOnSuspicious: "Warn before opening suspicious sites",
    warnOnSuspiciousHint: "Sites known to be malicious are always interrupted. With this on, strong warning signs such as look-alike domains are too.",
    preloadBlocking: "Block known dangerous sites before they load",
    preloadBlockingHint: "Keeps a list of known malicious domains in your browser and stops them before any of their content loads. Nothing about your browsing is sent to download the list.",
    downloadChecks: "Check downloads",
    downloadChecksHint: "Checks where a download comes from and its file name. Browsers do not let extensions read the file itself.",
    hoverChecks: "Check links when you hover over them",
    hoverChecksHint: "Needs permission to run on the pages you visit. Only the link address is checked, never the page content. Off by default.",
    assistant: "On-screen assistant",
    assistantHint: "A small SENTINEL button on web pages that warns you about the site, shows which cookies and trackers it uses, warns before you type a password on a suspicious page, and answers questions. Needs permission to run on pages and read cookie names. Cookie values are never read. Off by default.",
    language: "Language",
    languageAuto: "Same as the browser",
    privacy: "Privacy",
    privacyLegend: "What is sent to SENTINEL for each page",
    privacyFull: "The full address",
    privacyFullHint: "(recommended). Recognises specific malicious links on otherwise normal sites. Addresses are checked and not stored.",
    privacyHost: "Only the domain name",
    privacyHostHint: ". More private; malicious links on shared hosting may be missed.",
    keepLocalAlerts: "Keep a list of recent alerts in this browser",
    keepLocalAlertsHint: "Stored only in this browser. Shown in the popup.",
    clearAlerts: "Clear alert list",
    clearCache: "Clear cached results",
    neverCollected: "Never collected: passwords, form contents, card details, cookie values, messages, or the content of the pages you visit.",
    lists: "Your lists",
    allowlist: "Never check these sites",
    blocklist: "Always block these sites",
    oneDomain: "One domain per line. Subdomains are included.",
    blockedHint: "Blocked sites are stopped before they load and show a warning page.",
    saveLists: "Save lists",
    account: "SENTINEL account",
    server: "Server",
    serverAddress: "SENTINEL server address",
    change: "Change",
    serverHint: "Changing the server disconnects this extension from the current one.",
    saved: "Saved.",
    listsSaved: "Lists saved.",
    ignored: (entries: string) => `Saved. Ignored entries that are not domain names: ${entries}`,
    permissionDenied: "That feature needs permission to run on web pages; nothing was changed.",
    alertsCleared: "Alert list cleared.",
    cacheCleared: "Cached results cleared.",
    notEnrolled: "This extension is not connected to the server yet, so sites are not being checked.",
    connectNow: "Connect now",
    linkedTo: "Linked to ",
    yourAccount: "your account",
    syncOn: "Warnings are recorded in your SENTINEL history (only the domain and the verdict). You can turn this off in your dashboard settings.",
    syncOff: "Nothing is recorded in your account. You can choose to keep a history of warnings in your dashboard settings.",
    unlink: "Unlink from account",
    linkIntro: "Protection works without an account. Linking lets you see this browser in your dashboard and, if you choose, keep a history of warnings.",
    linkHow: "In your SENTINEL dashboard, open Browser protection and create a link code, then enter it here.",
    linkCode: "Link code",
    link: "Link",
    enterCode: "Enter the code shown in your dashboard.",
    useHttps: "Use an https:// address, except for a server on this computer.",
    fullAddress: "Enter a full address, such as https://sentinel.example.org",
    serverPermission: "The extension needs permission to contact that server; nothing was changed.",
    serverChanged: "Server changed. Connecting…",
    connected: "Connected to the new server.",
    serverUnreachable: (message: string) => `Saved, but the server could not be reached: ${message}`,
  },
  assistant: {
    open: "Open the SENTINEL assistant",
    close: "Close",
    title: "SENTINEL assistant",
    thisSite: "This site",
    checking: "Checking this site…",
    cookies: "Cookies",
    cookiesNone: "This site has not set any cookies that SENTINEL can see.",
    cookiesSummary: (total: number, third: number) =>
      `${total} cookie${total === 1 ? "" : "s"}${third ? `, ${third} from other companies` : ""}.`,
    session: "until you close the browser",
    days: (n: number) => (n < 1 ? "less than a day" : n === 1 ? "1 day" : `${n} days`),
    thirdParty: "other company",
    firstParty: "this site",
    trackers: "Trackers",
    trackersNone: "No known trackers were seen loading on this page.",
    trackersSummary: (n: number) => `${n} known tracker${n === 1 ? "" : "s"} loaded on this page:`,
    ask: "Ask a question",
    placeholder: "Is this site trustworthy? What do these cookies do?",
    send: "Ask",
    thinking: "Thinking…",
    aiLabel: "AI-written answer. Check important things yourself.",
    builtInLabel: "Built-in answer (the AI assistant is not available on this server).",
    suggestions: ["Can I trust this site?", "What are these cookies for?", "How do I block trackers?"],
    passwordTitle: "Stop before typing your password",
    passwordBody: (label: string) =>
      `SENTINEL rates this site “${label}”. If you were asked to sign in from a link in a message or email, close this page and open the real site yourself.`,
    dismiss: "Dismiss",
    warningTitle: (label: string) => `SENTINEL: ${label}`,
    neverValues: "Only cookie names are shown. SENTINEL never reads cookie values.",
    error: "The assistant could not answer right now.",
    notReady: "The assistant needs permission to read cookie names. Turn it on again in the settings.",
  },
  answers: {
    trustWarning: (host: string, label: string, sign: string) =>
      `SENTINEL rates ${host} “${label}”${sign ? ` because: ${sign}` : ""}. Do not enter passwords, card details or personal information here. If you need this service, type its address yourself or use its official app.`,
    trustClear: (host: string) =>
      `SENTINEL found no known threat on ${host}. That is not a guarantee: new scam sites appear every day. Check that the address is exactly the one you expect before signing in or paying.`,
    trustUnknown: (host: string) =>
      `SENTINEL could not check ${host} right now, so treat it with care. Check the address carefully before entering anything private.`,
    cookies: (total: number, third: number) =>
      `Cookies are small files websites store in your browser. This page uses ${total}. Some keep you signed in or remember settings; ${third ? `${third} come from other companies and are usually used for advertising or measuring visits. ` : ""}You can clear cookies in your browser's privacy settings, or block third-party cookies there.`,
    trackers: (names: string) =>
      names
        ? `This page loads ${names}. Trackers record what you view so advertisers or analytics companies can build a profile. You can reduce this by blocking third-party cookies in your browser settings or using a content blocker.`
        : "SENTINEL did not see known trackers on this page. Trackers record what you view for advertising or analytics; blocking third-party cookies in your browser settings reduces them.",
    password: (host: string, label: string) =>
      `Only type your password on a site you opened yourself. SENTINEL rates ${host} “${label}”. Password managers help: they only fill in passwords on the real site.`,
    fallback:
      "I can answer questions about this site, its cookies and trackers, passwords and common scams. Try one of the suggested questions.",
  },
};

export type Dictionary = typeof en;

const ar: Dictionary = {
  verdicts: {
    dangerous: { label: "خطير", detail: "هذا الموقع مدرج في مصادر معلومات التهديدات على أنه ضار." },
    suspicious: { label: "مشبوه", detail: "علامات تحذير قوية، مثل تقليد اسم علامة تجارية معروفة." },
    caution: { label: "انتبه", detail: "بعض علامات التحذير. كن حذرًا مع كلمات المرور والدفع هنا." },
    no_known_threat: { label: "لا يوجد تهديد معروف", detail: "لم تجد الفحوصات أي مشكلة معروفة، وهذا ليس ضمانًا للأمان." },
    unavailable: { label: "تعذّر الفحص", detail: "لم يتمكن SENTINEL من فحص هذا الموقع، لذلك هو غير محمي الآن." },
    skipped: { label: "لم يُفحص", detail: "لا تُفحص العناوين المحلية وعناوين الشبكات الخاصة." },
    blocked_by_you: { label: "محظور من قِبلك", detail: "هذا الموقع في قائمة الحظر الخاصة بك." },
    allowed_by_you: { label: "لم يُفحص (مسموح من قِبلك)", detail: "هذا الموقع في قائمة السماح الخاصة بك، لذلك لا يفحصه SENTINEL." },
  },
  time: {
    justNow: "الآن",
    minutes: (n) => `قبل ${n} دقيقة`,
    hours: (n) => `قبل ${n} ساعة`,
  },
  popup: {
    protection: "الحماية",
    protectionToggle: "إيقاف الحماية مؤقتًا أو استئنافها",
    protectionOn: "الحماية مفعّلة",
    protectionPaused: "الحماية متوقفة مؤقتًا",
    notConnected: "غير متصل",
    recentAlerts: "التنبيهات الأخيرة",
    clear: "مسح",
    openDashboard: "فتح لوحة التحكم",
    settings: "الإعدادات",
    checking: "جارٍ فحص هذه الصفحة…",
    openSite: "افتح موقعًا لترى حالته هنا.",
    pausedNotChecked: "الحماية متوقفة مؤقتًا، لذلك لم تُفحص هذه الصفحة.",
    onlyWeb: "يفحص SENTINEL صفحات الويب فقط (http وhttps).",
    checked: (when) => `فُحص ${when}`,
    fullScan: "إجراء فحص كامل",
    connect: "اتصال",
    notConnectedTitle: "غير متصل بخادم SENTINEL",
    notConnectedBody: (server) => `لا تُفحص المواقع حاليًا. تعذّر الوصول إلى الخادم ${server} عند بدء الإضافة.`,
    noAlerts: "لا توجد تنبيهات. ستظهر هنا التحذيرات التي تراها.",
    preloaded: (count) => `يُحظر ${count.toLocaleString("ar")} موقعًا خطيرًا معروفًا قبل أن يُحمَّل.`,
  },
  warning: {
    title: "تحذير: أوقف SENTINEL هذه الصفحة",
    loading: "جارٍ تحميل تفاصيل هذا التحذير…",
    headlineDangerous: "هذا الموقع معروف بأنه خطير",
    headlineSuspicious: "يبدو هذا الموقع تقليدًا لموقع آخر",
    headlineBlocked: "لقد حظرت هذا الموقع",
    adviceDangerous: "لا تُدخل كلمات مرور أو بيانات دفع أو معلومات شخصية، ولا تنزّل أي شيء منه.",
    adviceSuspicious: "إذا كنت تتوقع خدمة معروفة، فاكتب عنوانها بنفسك أو استخدم تطبيقها الرسمي.",
    adviceBlocked: "يمكنك إزالته من قائمة الحظر في إعدادات الإضافة.",
    riskLevel: (label) => `مستوى الخطر: ${label}.`,
    why: "لماذا أوقف SENTINEL هذه الصفحة",
    source: (name) => `المصدر: ${name}`,
    goBack: "العودة إلى الأمان",
    understand: "أفهم المخاطر",
    proceedDangerous: "تُدرج مصادر معلومات التهديدات هذا العنوان على أنه ضار. قد يعرّض الاستمرار جهازك أو حساباتك للخطر. لن يحذّرك SENTINEL من هذا الموقع مجددًا حتى تعيد تشغيل المتصفح.",
    proceedSuspicious: "هذه علامات تحذير وليست دليلًا. إذا كنت متأكدًا أن هذا هو الموقع الذي تقصده فيمكنك المتابعة. لن يحذّرك SENTINEL منه مجددًا حتى تعيد تشغيل المتصفح.",
    continueTo: (host) => `المتابعة إلى ${host}`,
    noAddress: "لم يُحدَّد أي عنوان.",
    stopped: "أوقف SENTINEL هذه الصفحة",
    back: "رجوع",
    notChecked: "تعذّر فحص هذا العنوان.",
    preloadReason: "مدرج في قائمة SENTINEL للنطاقات الضارة المعروفة",
    preloadExplanation: "هذا النطاق موجود في قائمة المواقع الخطيرة المعروفة التي تحفظها إضافة SENTINEL في متصفحك، لذلك حُظر قبل أن يُحمَّل.",
    preloadSource: "قائمة حظر SENTINEL (في متصفحك)",
  },
  notifications: {
    downloadPaused: (label) => `أُوقف تنزيل ${label} مؤقتًا`,
    cancel: "إلغاء التنزيل",
    keep: "الاحتفاظ به على أي حال",
    downloadsPanel: "افتح لوحة التنزيلات لإلغائه أو استئنافه.",
    notChecked: "لم يُفحص",
    notCheckedBody: "يمكن فحص عناوين الويب العامة فقط (http وhttps).",
    scanLink: "فحص الرابط باستخدام SENTINEL",
    checkPage: "فحص هذه الصفحة باستخدام SENTINEL",
  },
  options: {
    pageTitle: "إعدادات SENTINEL Protect",
    title: "الإعدادات",
    protection: "الحماية",
    paused: "إيقاف الحماية مؤقتًا",
    pausedHint: "أثناء الإيقاف لا تُفحص أي مواقع ولا تظهر تحذيرات.",
    warnOnSuspicious: "التحذير قبل فتح المواقع المشبوهة",
    warnOnSuspiciousHint: "تُوقَف المواقع المعروفة بأنها ضارة دائمًا. مع تفعيل هذا الخيار تُوقَف أيضًا المواقع ذات علامات التحذير القوية مثل النطاقات المقلِّدة.",
    preloadBlocking: "حظر المواقع الخطيرة المعروفة قبل تحميلها",
    preloadBlockingHint: "تحفظ الإضافة قائمة بالنطاقات الضارة المعروفة في متصفحك وتوقفها قبل تحميل أي محتوى منها. لا يُرسل أي شيء عن تصفحك لتنزيل القائمة.",
    downloadChecks: "فحص التنزيلات",
    downloadChecksHint: "يفحص مصدر التنزيل واسم الملف. لا تسمح المتصفحات للإضافات بقراءة الملف نفسه.",
    hoverChecks: "فحص الروابط عند تمرير المؤشر فوقها",
    hoverChecksHint: "يتطلب إذنًا بالعمل على الصفحات التي تزورها. يُفحص عنوان الرابط فقط، ولا يُقرأ محتوى الصفحة. متوقف افتراضيًا.",
    assistant: "المساعد على الشاشة",
    assistantHint: "زر صغير من SENTINEL على صفحات الويب يحذّرك من الموقع، ويعرض ملفات تعريف الارتباط وأدوات التتبع التي يستخدمها، وينبّهك قبل كتابة كلمة المرور في صفحة مشبوهة، ويجيب عن أسئلتك. يتطلب إذنًا بالعمل على الصفحات وقراءة أسماء ملفات تعريف الارتباط. لا تُقرأ قيمها أبدًا. متوقف افتراضيًا.",
    language: "اللغة",
    languageAuto: "مثل لغة المتصفح",
    privacy: "الخصوصية",
    privacyLegend: "ما يُرسل إلى SENTINEL لكل صفحة",
    privacyFull: "العنوان الكامل",
    privacyFullHint: "(موصى به). يتعرّف على روابط ضارة محددة في مواقع عادية. تُفحص العناوين ولا تُخزَّن.",
    privacyHost: "اسم النطاق فقط",
    privacyHostHint: ". خصوصية أكبر؛ لكن قد تفوت الروابط الضارة على الاستضافات المشتركة.",
    keepLocalAlerts: "الاحتفاظ بقائمة التنبيهات الأخيرة في هذا المتصفح",
    keepLocalAlertsHint: "تُخزَّن في هذا المتصفح فقط وتظهر في النافذة المنبثقة.",
    clearAlerts: "مسح قائمة التنبيهات",
    clearCache: "مسح النتائج المخزّنة",
    neverCollected: "لا يُجمع أبدًا: كلمات المرور، ومحتوى النماذج، وبيانات البطاقات، وقيم ملفات تعريف الارتباط، والرسائل، ومحتوى الصفحات التي تزورها.",
    lists: "قوائمك",
    allowlist: "لا تفحص هذه المواقع أبدًا",
    blocklist: "احظر هذه المواقع دائمًا",
    oneDomain: "نطاق واحد في كل سطر. تشمل النطاقات الفرعية.",
    blockedHint: "تُوقف المواقع المحظورة قبل تحميلها وتظهر صفحة تحذير.",
    saveLists: "حفظ القوائم",
    account: "حساب SENTINEL",
    server: "الخادم",
    serverAddress: "عنوان خادم SENTINEL",
    change: "تغيير",
    serverHint: "تغيير الخادم يفصل هذه الإضافة عن الخادم الحالي.",
    saved: "تم الحفظ.",
    listsSaved: "تم حفظ القوائم.",
    ignored: (entries) => `تم الحفظ. تم تجاهل إدخالات ليست أسماء نطاقات: ${entries}`,
    permissionDenied: "تحتاج هذه الميزة إلى إذن بالعمل على صفحات الويب؛ لم يتغير شيء.",
    alertsCleared: "تم مسح قائمة التنبيهات.",
    cacheCleared: "تم مسح النتائج المخزّنة.",
    notEnrolled: "هذه الإضافة غير متصلة بالخادم بعد، لذلك لا تُفحص المواقع.",
    connectNow: "اتصل الآن",
    linkedTo: "مرتبطة بـ ",
    yourAccount: "حسابك",
    syncOn: "تُسجَّل التحذيرات في سجل SENTINEL الخاص بك (النطاق والحكم فقط). يمكنك إيقاف ذلك من إعدادات لوحة التحكم.",
    syncOff: "لا يُسجَّل أي شيء في حسابك. يمكنك اختيار الاحتفاظ بسجل للتحذيرات من إعدادات لوحة التحكم.",
    unlink: "فك الارتباط بالحساب",
    linkIntro: "تعمل الحماية دون حساب. يتيح لك الربط رؤية هذا المتصفح في لوحة التحكم، والاحتفاظ بسجل للتحذيرات إن أردت.",
    linkHow: "في لوحة تحكم SENTINEL افتح «حماية المتصفح» وأنشئ رمز ربط، ثم أدخله هنا.",
    linkCode: "رمز الربط",
    link: "ربط",
    enterCode: "أدخل الرمز الظاهر في لوحة التحكم.",
    useHttps: "استخدم عنوانًا يبدأ بـ https://‏، إلا إذا كان الخادم على هذا الجهاز.",
    fullAddress: "أدخل عنوانًا كاملًا، مثل https://sentinel.example.org",
    serverPermission: "تحتاج الإضافة إلى إذن للاتصال بهذا الخادم؛ لم يتغير شيء.",
    serverChanged: "تم تغيير الخادم. جارٍ الاتصال…",
    connected: "تم الاتصال بالخادم الجديد.",
    serverUnreachable: (message) => `تم الحفظ، لكن تعذّر الوصول إلى الخادم: ${message}`,
  },
  assistant: {
    open: "فتح مساعد SENTINEL",
    close: "إغلاق",
    title: "مساعد SENTINEL",
    thisSite: "هذا الموقع",
    checking: "جارٍ فحص هذا الموقع…",
    cookies: "ملفات تعريف الارتباط",
    cookiesNone: "لم يضع هذا الموقع أي ملفات تعريف ارتباط يمكن لـ SENTINEL رؤيتها.",
    cookiesSummary: (total, third) => `${total} ملف تعريف ارتباط${third ? `، منها ${third} من شركات أخرى` : ""}.`,
    session: "حتى إغلاق المتصفح",
    days: (n) => (n < 1 ? "أقل من يوم" : n === 1 ? "يوم واحد" : `${n} يومًا`),
    thirdParty: "شركة أخرى",
    firstParty: "هذا الموقع",
    trackers: "أدوات التتبع",
    trackersNone: "لم تُرصد أدوات تتبع معروفة تُحمَّل في هذه الصفحة.",
    trackersSummary: (n) => `حُمّلت ${n} من أدوات التتبع المعروفة في هذه الصفحة:`,
    ask: "اطرح سؤالًا",
    placeholder: "هل يمكنني الوثوق بهذا الموقع؟ ما فائدة ملفات تعريف الارتباط هذه؟",
    send: "اسأل",
    thinking: "جارٍ التفكير…",
    aiLabel: "إجابة كتبها الذكاء الاصطناعي. تحقق من الأمور المهمة بنفسك.",
    builtInLabel: "إجابة مدمجة (مساعد الذكاء الاصطناعي غير متاح على هذا الخادم).",
    suggestions: ["هل يمكنني الوثوق بهذا الموقع؟", "ما فائدة ملفات تعريف الارتباط هذه؟", "كيف أحظر أدوات التتبع؟"],
    passwordTitle: "توقف قبل كتابة كلمة المرور",
    passwordBody: (label) =>
      `يصنّف SENTINEL هذا الموقع «${label}». إذا طُلب منك تسجيل الدخول من رابط في رسالة أو بريد، فأغلق هذه الصفحة وافتح الموقع الحقيقي بنفسك.`,
    dismiss: "إخفاء",
    warningTitle: (label) => `SENTINEL: ${label}`,
    neverValues: "تُعرض أسماء ملفات تعريف الارتباط فقط. لا يقرأ SENTINEL قيمها أبدًا.",
    error: "تعذّر على المساعد الإجابة الآن.",
    notReady: "يحتاج المساعد إلى إذن لقراءة أسماء ملفات تعريف الارتباط. فعّله مرة أخرى من الإعدادات.",
  },
  answers: {
    trustWarning: (host, label, sign) =>
      `يصنّف SENTINEL الموقع ${host} «${label}»${sign ? ` بسبب: ${sign}` : ""}. لا تُدخل هنا كلمات مرور أو بيانات بطاقة أو معلومات شخصية. إذا كنت تحتاج هذه الخدمة فاكتب عنوانها بنفسك أو استخدم تطبيقها الرسمي.`,
    trustClear: (host) =>
      `لم يجد SENTINEL أي تهديد معروف في ${host}. هذا ليس ضمانًا، فمواقع الاحتيال الجديدة تظهر كل يوم. تأكد أن العنوان هو بالضبط ما تتوقعه قبل تسجيل الدخول أو الدفع.`,
    trustUnknown: (host) =>
      `تعذّر على SENTINEL فحص ${host} الآن، لذلك تعامل معه بحذر وتحقق من العنوان جيدًا قبل إدخال أي معلومات خاصة.`,
    cookies: (total, third) =>
      `ملفات تعريف الارتباط ملفات صغيرة تحفظها المواقع في متصفحك. تستخدم هذه الصفحة ${total} منها. بعضها يبقيك مسجّل الدخول أو يتذكر إعداداتك؛ ${third ? `و${third} منها من شركات أخرى وتُستخدم عادة للإعلانات أو قياس الزيارات. ` : ""}يمكنك مسحها أو حظر ملفات الطرف الثالث من إعدادات الخصوصية في المتصفح.`,
    trackers: (names) =>
      names
        ? `تحمّل هذه الصفحة ${names}. تسجّل أدوات التتبع ما تشاهده لتبني شركات الإعلان أو التحليلات ملفًا عنك. يمكنك تقليل ذلك بحظر ملفات تعريف الارتباط من الطرف الثالث في إعدادات المتصفح أو باستخدام أداة حظر المحتوى.`
        : "لم يرصد SENTINEL أدوات تتبع معروفة في هذه الصفحة. تسجّل أدوات التتبع ما تشاهده لأغراض الإعلان أو التحليل، ويقلّلها حظر ملفات تعريف الارتباط من الطرف الثالث في إعدادات المتصفح.",
    password: (host, label) =>
      `اكتب كلمة المرور فقط في موقع فتحته بنفسك. يصنّف SENTINEL الموقع ${host} «${label}». تساعدك برامج إدارة كلمات المرور، فهي لا تملأ كلمة المرور إلا في الموقع الحقيقي.`,
    fallback: "يمكنني الإجابة عن أسئلة حول هذا الموقع وملفات تعريف الارتباط وأدوات التتبع وكلمات المرور وأساليب الاحتيال الشائعة. جرّب أحد الأسئلة المقترحة.",
  },
};

const DICTIONARIES: Record<Language, Dictionary> = { en, ar };
let current: Language = "en";

export function resolveLanguage(setting: LanguageSetting | undefined, uiLanguage: string): Language {
  if (setting === "en" || setting === "ar") return setting;
  return uiLanguage.toLowerCase().startsWith("ar") ? "ar" : "en";
}

function browserLanguage(): string {
  try {
    return chrome.i18n?.getUILanguage?.() ?? navigator.language;
  } catch {
    return typeof navigator === "undefined" ? "en" : navigator.language;
  }
}

export function setLanguage(language: Language) {
  current = language;
}

export function language(): Language {
  return current;
}

export function t(): Dictionary {
  return DICTIONARIES[current];
}

export function dictionary(language: Language): Dictionary {
  return DICTIONARIES[language];
}

/** Reads the language setting straight from storage, so any context can call it. */
export async function initLanguage(): Promise<Language> {
  let setting: LanguageSetting | undefined;
  try {
    const stored = await chrome.storage.local.get("settings");
    setting = (stored.settings as { language?: LanguageSetting } | undefined)?.language;
  } catch {
    setting = undefined;
  }
  current = resolveLanguage(setting, browserLanguage());
  return current;
}

function lookup(path: string): string | null {
  let value: unknown = t();
  for (const part of path.split(".")) {
    if (value && typeof value === "object" && part in value) value = (value as Record<string, unknown>)[part];
    else return null;
  }
  return typeof value === "string" ? value : null;
}

export function localizeDocument(root: Document = document) {
  root.documentElement.lang = current;
  root.documentElement.dir = current === "ar" ? "rtl" : "ltr";
  for (const element of root.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const text = lookup(element.dataset.i18n ?? "");
    if (text !== null) element.textContent = text;
  }
  for (const element of root.querySelectorAll<HTMLElement>("[data-i18n-placeholder]")) {
    const text = lookup(element.dataset.i18nPlaceholder ?? "");
    if (text !== null) element.setAttribute("placeholder", text);
  }
  for (const element of root.querySelectorAll<HTMLElement>("[data-i18n-aria-label]")) {
    const text = lookup(element.dataset.i18nAriaLabel ?? "");
    if (text !== null) element.setAttribute("aria-label", text);
  }
  for (const element of root.querySelectorAll<HTMLElement>("[data-i18n-title]")) {
    const text = lookup(element.dataset.i18nTitle ?? "");
    if (text !== null) element.setAttribute("title", text);
  }
}

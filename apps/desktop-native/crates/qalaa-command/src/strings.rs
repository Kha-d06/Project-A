//! English and Arabic text for the command centre. Every key exists in both.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ar,
}

impl Lang {
    /// From `--lang`, `QALAA_LANG` or the system `LANG`.
    pub fn detect(arg: Option<&str>) -> Self {
        let pick = arg
            .map(str::to_owned)
            .or_else(|| std::env::var("QALAA_LANG").ok())
            .or_else(|| std::env::var("LANG").ok())
            .unwrap_or_default();
        if pick.to_ascii_lowercase().starts_with("ar") {
            Lang::Ar
        } else {
            Lang::En
        }
    }

    pub fn rtl(self) -> bool {
        self == Lang::Ar
    }
}

pub fn t(lang: Lang, key: &str) -> &'static str {
    let en = EN.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    let ar = AR.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    match lang {
        Lang::En => en.unwrap_or("?"),
        Lang::Ar => ar.or(en).unwrap_or("?"),
    }
}

pub const EN: &[(&str, &str)] = &[
    ("safepay.open", "Open SafePay"),
    (
        "safepay.hint",
        "A clean browser window for banking and shopping: no extensions, nothing saved, deleted when you close it.",
    ),
    ("nav.credentials", "Credentials"),
    ("cred.title", "Who opens your keys and passwords"),
    (
        "cred.intro",
        "Qalaa tells you when a program that isn't expected to opens SSH keys, .env files, cloud credentials or a browser's saved passwords and cookies. Pause it if you don't recognise it.",
    ),
    ("cred.none", "No unexpected program has opened your credentials."),
    ("cred.mode.every_open", "Watching every open (on-access helper running)."),
    (
        "cred.mode.polling",
        "Checking open files every few seconds. A very quick read between two checks can be missed; on Linux, turn on blocking before files run to see every open.",
    ),
    (
        "cred.mode.unavailable",
        "Not available on this system yet: seeing which program has a file open needs a system query Qalaa doesn't have on Windows.",
    ),
    ("cred.kind.ssh_key", "SSH key"),
    ("cred.kind.env_file", ".env file"),
    ("cred.kind.cloud_credentials", "Cloud credentials"),
    ("cred.kind.browser_secrets", "Browser passwords and cookies"),
    ("cred.state.suspended", "Paused"),
    ("cred.state.terminated", "Stopped"),
    ("cred.suspend", "Pause"),
    ("cred.resume", "Resume"),
    ("cred.terminate", "Stop"),
    ("cred.allow", "Allow program"),
    ("cred.dismiss", "Dismiss"),
    ("action.review_credentials", "A program opened your credentials"),
    ("action.review_credentials.detail", "Pause it if you don't recognise it, or allow it if you do."),
    ("action.review_credentials.button", "Review"),
    ("toggle.credentialGuard", "Alert when unexpected programs open keys and passwords"),
    ("clip.clear", "Clear now"),
    ("toggle.clipboardGuard", "Wipe secrets from the clipboard after 30 seconds"),
    ("clip.kind.private_key", "A private key"),
    ("clip.kind.cloud_key", "A cloud access key"),
    ("clip.kind.api_token", "An API token"),
    ("clip.kind.jwt", "A sign-in token"),
    ("clip.kind.env_secret", "A password or secret setting"),
    ("clip.kind.high_entropy", "Something that looks like a password"),
    ("clip.kind.copied_from_qalaa", "A code copied from Qalaa"),
    ("toggle.safeDns", "Safe DNS: block malicious sites for every app"),
    ("action.review_keyboard", "A new keyboard was connected"),
    (
        "action.review_keyboard.detail",
        "If you didn't just plug in a keyboard, unplug the device now: some USB sticks pretend to be keyboards to type commands.",
    ),
    ("action.review_keyboard.button", "I plugged it in"),
    ("nav.ports", "Ports"),
    ("ports.title", "Programs accepting connections"),
    (
        "ports.intro",
        "Programs listening for connections from other machines. Qalaa tells you when a new one appears; you decide whether it's expected.",
    ),
    ("ports.none", "Nothing on this computer accepts connections from other machines."),
    ("ports.new", "New"),
    ("ports.blocked", "Blocked"),
    ("ports.local", "This computer only"),
    ("ports.reachable", "Reachable from other machines"),
    ("ports.trust", "Expected"),
    ("ports.block", "Block port"),
    ("ports.unblock", "Allow again"),
    (
        "ports.prompt",
        "Blocking asks for your system password. It only stops connections from other machines and can be undone here.",
    ),
    ("ports.unknown_program", "Unknown program"),
    ("action.review_listeners", "A program started accepting connections"),
    ("action.review_listeners.detail", "Check that you expected it, or block its port."),
    ("app.title", "Qalaa"),
    ("nav.home", "Home"),
    ("nav.about", "About"),
    ("state.protected", "Protected"),
    ("state.attention", "Needs attention"),
    ("state.at_risk", "At risk"),
    ("state.offline", "Not connected"),
    ("score", "Protection score"),
    ("checks", "What's protecting this computer"),
    ("actions", "To do"),
    ("actions.none", "Nothing needs doing right now."),
    ("dock", "Quick settings"),
    ("check.signatures", "Malware fingerprints"),
    ("check.realtime", "Real-time file checks"),
    ("check.ransomware", "Ransomware watch"),
    ("check.last_scan", "Last scan"),
    ("check.network", "Home network"),
    ("check.backup", "Encrypted backup"),
    ("status.ok", "On and up to date"),
    ("status.attention", "Needs a look"),
    ("status.off", "Off"),
    ("status.unknown", "Not checked yet"),
    ("fresh.never", "never"),
    ("fresh.just_now", "just now"),
    ("action.review_threats", "Review recent threats"),
    (
        "action.review_threats.detail",
        "Files with warning signs were found in the last week.",
    ),
    ("action.turn_on_realtime", "Turn on real-time checks"),
    ("action.turn_on_realtime.detail", "New downloads aren't being checked."),
    ("action.update_signatures", "Update malware fingerprints"),
    ("action.update_signatures.detail", "The list is missing or more than two days old."),
    ("action.quick_scan", "Run a quick scan"),
    (
        "action.quick_scan.detail",
        "Your watched folders haven't been scanned for two weeks.",
    ),
    ("action.set_up_backup", "Set up an encrypted backup"),
    (
        "action.set_up_backup.detail",
        "The best protection against ransomware and a lost laptop.",
    ),
    ("action.scan_network", "Scan your home network"),
    ("action.scan_network.detail", "See every device on your Wi-Fi and any open doors."),
    ("action.install_update", "Install the Qalaa update"),
    ("action.install_update.detail", "A newer version is ready."),
    ("action.go", "Do it"),
    ("toggle.watchEnabled", "Check new downloads"),
    ("toggle.onAccessScan", "Block before files run (Linux)"),
    ("toggle.ransomwareWatch", "Watch for ransomware"),
    ("toggle.networkWatch", "Rescan home network every 6 hours"),
    ("toggle.cloudLookup", "Fingerprint lookups (sends 6 characters only)"),
    ("toggle.unavailable", "Not available on this system"),
    ("palette.placeholder", "Type a command"),
    ("palette.hint", "Ctrl+K or ⌘K for commands"),
    ("palette.quick_scan", "Run a quick scan"),
    ("palette.update_signatures", "Update malware fingerprints"),
    ("palette.about", "About Qalaa"),
    ("palette.home", "Go to Home"),
    ("palette.toggle", "Switch"),
    (
        "offline.body",
        "The Qalaa background service isn't running. Start Qalaa, then try again.",
    ),
    ("retry", "Try again"),
    ("busy", "Working…"),
    ("classic", "This view is still in the classic Qalaa app."),
    (
        "about.body",
        "Qalaa is a free security suite. This native command centre is replacing the classic app one view at a time.",
    ),
    ("silent", "Silent mode until"),
];

pub const AR: &[(&str, &str)] = &[
    ("safepay.open", "افتح الدفع الآمن"),
    (
        "safepay.hint",
        "نافذة متصفح نظيفة للمصارف والتسوق: بلا إضافات ولا يُحفظ شيء، وتُحذف عند إغلاقها.",
    ),
    ("nav.credentials", "بيانات الاعتماد"),
    ("cred.title", "من يفتح مفاتيحك وكلمات مرورك"),
    (
        "cred.intro",
        "تنبّهك قلعة عندما يفتح برنامج غير متوقع مفاتيح SSH أو ملفات .env أو بيانات الاعتماد السحابية أو كلمات المرور وملفات تعريف الارتباط المحفوظة في المتصفح. أوقفه مؤقتًا إن لم تتعرّف عليه.",
    ),
    ("cred.none", "لم يفتح أي برنامج غير متوقع بيانات اعتمادك."),
    ("cred.mode.every_open", "تُراقَب كل عملية فتح (المساعد يعمل)."),
    (
        "cred.mode.polling",
        "تُفحص الملفات المفتوحة كل بضع ثوانٍ. قد تفوت قراءة سريعة جدًا بين فحصين؛ في لينكس فعّل الحظر قبل تشغيل الملفات لرؤية كل عملية فتح.",
    ),
    (
        "cred.mode.unavailable",
        "غير متاح على هذا النظام بعد: معرفة البرنامج الذي يفتح ملفًا تحتاج إلى استعلام نظام لا تملكه قلعة على ويندوز.",
    ),
    ("cred.kind.ssh_key", "مفتاح SSH"),
    ("cred.kind.env_file", "ملف .env"),
    ("cred.kind.cloud_credentials", "بيانات اعتماد سحابية"),
    ("cred.kind.browser_secrets", "كلمات مرور المتصفح وملفات تعريف الارتباط"),
    ("cred.state.suspended", "موقوف مؤقتًا"),
    ("cred.state.terminated", "أُنهي"),
    ("cred.suspend", "إيقاف مؤقت"),
    ("cred.resume", "استئناف"),
    ("cred.terminate", "إنهاء"),
    ("cred.allow", "السماح للبرنامج"),
    ("cred.dismiss", "تجاهل"),
    ("action.review_credentials", "فتح برنامج بيانات اعتمادك"),
    ("action.review_credentials.detail", "أوقفه مؤقتًا إن لم تتعرّف عليه، أو اسمح له إن كنت تعرفه."),
    ("action.review_credentials.button", "راجِع"),
    ("toggle.credentialGuard", "نبّهني عندما تفتح برامج غير متوقعة المفاتيح وكلمات المرور"),
    ("clip.clear", "امسح الآن"),
    ("toggle.clipboardGuard", "امسح الأسرار من الحافظة بعد 30 ثانية"),
    ("clip.kind.private_key", "مفتاح خاص"),
    ("clip.kind.cloud_key", "مفتاح وصول سحابي"),
    ("clip.kind.api_token", "رمز API"),
    ("clip.kind.jwt", "رمز تسجيل دخول"),
    ("clip.kind.env_secret", "كلمة مرور أو إعداد سري"),
    ("clip.kind.high_entropy", "شيء يشبه كلمة مرور"),
    ("clip.kind.copied_from_qalaa", "رمز نُسخ من قلعة"),
    ("toggle.safeDns", "DNS الآمن: احجب المواقع الخبيثة لكل التطبيقات"),
    ("action.review_keyboard", "وُصلت لوحة مفاتيح جديدة"),
    (
        "action.review_keyboard.detail",
        "إن لم توصل لوحة مفاتيح للتو، افصل الجهاز الآن: بعض وحدات USB تتظاهر بأنها لوحة مفاتيح لتكتب أوامر.",
    ),
    ("action.review_keyboard.button", "أنا وصلتها"),
    ("nav.ports", "المنافذ"),
    ("ports.title", "برامج تقبل الاتصالات"),
    (
        "ports.intro",
        "برامج تنتظر اتصالات من أجهزة أخرى. ينبهك قلعة عند ظهور برنامج جديد، وأنت تقرر إن كان متوقعًا.",
    ),
    ("ports.none", "لا شيء على هذا الحاسوب يقبل اتصالات من أجهزة أخرى."),
    ("ports.new", "جديد"),
    ("ports.blocked", "محظور"),
    ("ports.local", "هذا الحاسوب فقط"),
    ("ports.reachable", "يمكن الوصول إليه من أجهزة أخرى"),
    ("ports.trust", "متوقع"),
    ("ports.block", "احظر المنفذ"),
    ("ports.unblock", "اسمح مجددًا"),
    (
        "ports.prompt",
        "يطلب الحظر كلمة مرور النظام. يوقف الاتصالات من الأجهزة الأخرى فقط ويمكن التراجع عنه من هنا.",
    ),
    ("ports.unknown_program", "برنامج غير معروف"),
    ("action.review_listeners", "بدأ برنامج بقبول الاتصالات"),
    ("action.review_listeners.detail", "تأكد أنك تتوقعه، أو احظر منفذه."),
    ("app.title", "قلعة"),
    ("nav.home", "الرئيسية"),
    ("nav.about", "حول"),
    ("state.protected", "محمي"),
    ("state.attention", "يحتاج إلى انتباه"),
    ("state.at_risk", "في خطر"),
    ("state.offline", "غير متصل"),
    ("score", "درجة الحماية"),
    ("checks", "ما يحمي هذا الحاسوب"),
    ("actions", "مهام"),
    ("actions.none", "لا شيء يحتاج إلى إجراء الآن."),
    ("dock", "إعدادات سريعة"),
    ("check.signatures", "بصمات البرمجيات الخبيثة"),
    ("check.realtime", "فحص الملفات فوريًا"),
    ("check.ransomware", "مراقبة برامج الفدية"),
    ("check.last_scan", "آخر فحص"),
    ("check.network", "الشبكة المنزلية"),
    ("check.backup", "نسخة احتياطية مشفّرة"),
    ("status.ok", "يعمل ومحدّث"),
    ("status.attention", "يحتاج إلى مراجعة"),
    ("status.off", "متوقف"),
    ("status.unknown", "لم يُفحص بعد"),
    ("fresh.never", "أبدًا"),
    ("fresh.just_now", "الآن"),
    ("action.review_threats", "راجع التهديدات الأخيرة"),
    (
        "action.review_threats.detail",
        "عُثر على ملفات تظهر عليها علامات تحذير خلال الأسبوع الماضي.",
    ),
    ("action.turn_on_realtime", "شغّل الفحص الفوري"),
    ("action.turn_on_realtime.detail", "لا تُفحص التنزيلات الجديدة."),
    ("action.update_signatures", "حدّث بصمات البرمجيات الخبيثة"),
    ("action.update_signatures.detail", "القائمة غير موجودة أو مضى عليها أكثر من يومين."),
    ("action.quick_scan", "شغّل فحصًا سريعًا"),
    ("action.quick_scan.detail", "لم تُفحص المجلدات المراقبة منذ أسبوعين."),
    ("action.set_up_backup", "أعدّ نسخة احتياطية مشفّرة"),
    ("action.set_up_backup.detail", "أفضل حماية من برامج الفدية وفقدان الحاسوب."),
    ("action.scan_network", "افحص شبكتك المنزلية"),
    ("action.scan_network.detail", "اعرف كل جهاز على شبكتك وأي منافذ مفتوحة."),
    ("action.install_update", "ثبّت تحديث قلعة"),
    ("action.install_update.detail", "إصدار أحدث جاهز."),
    ("action.go", "نفّذ"),
    ("toggle.watchEnabled", "افحص التنزيلات الجديدة"),
    ("toggle.onAccessScan", "امنع الملفات قبل تشغيلها (لينكس)"),
    ("toggle.ransomwareWatch", "راقب برامج الفدية"),
    ("toggle.networkWatch", "أعد فحص الشبكة المنزلية كل 6 ساعات"),
    ("toggle.cloudLookup", "البحث عن البصمات (يرسل 6 أحرف فقط)"),
    ("toggle.unavailable", "غير متاح على هذا النظام"),
    ("palette.placeholder", "اكتب أمرًا"),
    ("palette.hint", "Ctrl+K أو ⌘K للأوامر"),
    ("palette.quick_scan", "شغّل فحصًا سريعًا"),
    ("palette.update_signatures", "حدّث بصمات البرمجيات الخبيثة"),
    ("palette.about", "حول قلعة"),
    ("palette.home", "اذهب إلى الرئيسية"),
    ("palette.toggle", "بدّل"),
    ("offline.body", "خدمة قلعة الخلفية لا تعمل. شغّل قلعة ثم حاول مجددًا."),
    ("retry", "حاول مجددًا"),
    ("busy", "جارٍ التنفيذ…"),
    ("classic", "هذه الشاشة ما زالت في تطبيق قلعة الكلاسيكي."),
    (
        "about.body",
        "قلعة مجموعة أمان مجانية. يحلّ مركز القيادة الأصلي هذا محل التطبيق الكلاسيكي شاشةً بعد أخرى.",
    ),
    ("silent", "الوضع الصامت حتى"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_exists_in_both_languages() {
        for (key, _) in EN {
            assert!(AR.iter().any(|(k, _)| k == key), "missing Arabic for {key}");
        }
        for (key, _) in AR {
            assert!(EN.iter().any(|(k, _)| k == key), "Arabic-only key {key}");
        }
        assert_eq!(t(Lang::Ar, "nav.home"), "الرئيسية");
        assert_eq!(t(Lang::En, "no.such.key"), "?");
    }

    #[test]
    fn detects_language() {
        assert_eq!(Lang::detect(Some("ar_AE.UTF-8")), Lang::Ar);
        assert_eq!(Lang::detect(Some("en_GB")), Lang::En);
        assert!(Lang::Ar.rtl());
    }
}

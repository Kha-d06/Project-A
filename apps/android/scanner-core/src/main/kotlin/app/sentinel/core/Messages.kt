package app.sentinel.core

/** The sentences shown for each finding and check, in English and Arabic. {0}, {1} are filled from args. */
object Messages {
    enum class Lang { EN, AR }

    private val findingsEn = mapOf(
        "known_malware" to "Matches known malware reported to MalwareBazaar.",
        "imitates_brand" to "Calls itself {0}, but is not the official {0} app and was not installed from an app store.",
        "accessibility_overlay" to "Can read everything on screen and draw over other apps. Banking trojans use this pair to steal passwords and codes.",
        "accessibility" to "Can read everything on screen and act for you (accessibility service).",
        "reads_sms" to "Can read your text messages, including one-time codes from your bank.",
        "device_admin" to "Asks to be a device administrator, which can make it hard to uninstall.",
        "notification_listener" to "Can read all your notifications, including codes and messages.",
        "installs_apps" to "Can install other apps.",
        "stalkerware" to "Has no icon, tracks location and can read messages, calls or audio. This is how monitoring software (stalkerware) behaves.",
        "hidden_icon" to "Has no icon on the home screen, which makes it hard to find and remove.",
        "old_target" to "Built for a very old Android version, so it gets its permissions without asking.",
        "sideloaded" to "Installed from outside an app store.",
        "eicar" to "The EICAR antivirus test file. It is harmless, and this shows scanning works.",
        "double_extension" to "Its name hides its real type (for example “invoice.pdf.apk”).",
        "disguised_program" to "Named like a document or picture, but it is actually a program.",
        "app_installer" to "An app installer file. Only install apps from an app store.",
    )

    private val findingsAr = mapOf(
        "known_malware" to "يطابق برمجية خبيثة معروفة مُبلغًا عنها في MalwareBazaar.",
        "imitates_brand" to "يسمّي نفسه {0} لكنه ليس تطبيق {0} الرسمي ولم يُثبَّت من متجر تطبيقات.",
        "accessibility_overlay" to "يستطيع قراءة كل ما على الشاشة والظهور فوق التطبيقات الأخرى. تستخدم أحصنة طروادة المصرفية هذا المزيج لسرقة كلمات المرور والرموز.",
        "accessibility" to "يستطيع قراءة كل ما على الشاشة والتصرف نيابة عنك (خدمة تسهيل الاستخدام).",
        "reads_sms" to "يستطيع قراءة رسائلك النصية، بما فيها رموز التحقق من البنك.",
        "device_admin" to "يطلب أن يكون مسؤولًا عن الجهاز، مما قد يصعّب إزالته.",
        "notification_listener" to "يستطيع قراءة كل إشعاراتك، بما فيها الرموز والرسائل.",
        "installs_apps" to "يستطيع تثبيت تطبيقات أخرى.",
        "stalkerware" to "بلا أيقونة، ويتتبع الموقع ويستطيع قراءة الرسائل أو المكالمات أو تسجيل الصوت. هكذا تتصرف برمجيات المراقبة (التجسس).",
        "hidden_icon" to "لا أيقونة له على الشاشة الرئيسية، مما يصعّب العثور عليه وإزالته.",
        "old_target" to "مصمَّم لإصدار قديم جدًا من أندرويد، فيحصل على صلاحياته دون أن يسأل.",
        "sideloaded" to "مثبّت من خارج متجر التطبيقات.",
        "eicar" to "ملف اختبار EICAR لمضادات الفيروسات. غير ضار، ويُظهر أن الفحص يعمل.",
        "double_extension" to "اسمه يخفي نوعه الحقيقي (مثل «invoice.pdf.apk»).",
        "disguised_program" to "اسمه يوحي بمستند أو صورة لكنه في الحقيقة برنامج.",
        "app_installer" to "ملف تثبيت تطبيق. ثبّت التطبيقات من متجر التطبيقات فقط.",
    )

    private val checksEn = mapOf(
        "patch.GOOD" to "Security updates are current (patch {0}).",
        "patch.WARN" to "Security updates are {1} months old (patch {0}). Check Settings → System → Software update.",
        "patch.BAD" to "Security updates are {1} months old (patch {0}). If no update is offered, this phone no longer gets fixes: avoid banking on it.",
        "patch.UNKNOWN" to "The security update date could not be read.",
        "screen_lock.GOOD" to "A screen lock is set.",
        "screen_lock.BAD" to "No screen lock. Anyone who picks up the phone can open your apps. Set a PIN in Settings → Security.",
        "screen_lock.UNKNOWN" to "The screen lock could not be checked.",
        "usb_debugging.BAD" to "USB debugging is on. A computer it is plugged into can install apps and read data. Turn it off in Developer options.",
        "developer_options.GOOD" to "Developer options are off.",
        "developer_options.WARN" to "Developer options are on. Turn them off if you do not need them.",
        "developer_options.UNKNOWN" to "Developer options could not be checked.",
        "root.GOOD" to "No signs that the phone is rooted.",
        "root.WARN" to "Signs that the phone is rooted ({0}). Rooting removes Android's protection between apps.",
        "unknown_sources.GOOD" to "No app is allowed to install other apps.",
        "unknown_sources.WARN" to "These apps may install other apps: {0}. Turn this off in Settings → Apps → Special app access → Install unknown apps.",
    )

    private val checksAr = mapOf(
        "patch.GOOD" to "التحديثات الأمنية حديثة (تحديث {0}).",
        "patch.WARN" to "عمر التحديثات الأمنية {1} أشهر (تحديث {0}). راجع الإعدادات ← النظام ← تحديث البرامج.",
        "patch.BAD" to "عمر التحديثات الأمنية {1} أشهر (تحديث {0}). إن لم يظهر تحديث، فهذا الهاتف لم يعد يتلقى إصلاحات: تجنّب استخدامه للخدمات المصرفية.",
        "patch.UNKNOWN" to "تعذّرت قراءة تاريخ التحديث الأمني.",
        "screen_lock.GOOD" to "قفل الشاشة مُعيَّن.",
        "screen_lock.BAD" to "لا يوجد قفل للشاشة. يستطيع أي شخص يمسك الهاتف فتح تطبيقاتك. عيّن رمز PIN من الإعدادات ← الأمان.",
        "screen_lock.UNKNOWN" to "تعذّر التحقق من قفل الشاشة.",
        "usb_debugging.BAD" to "تصحيح USB مُفعّل. يستطيع الحاسوب الموصول به تثبيت تطبيقات وقراءة البيانات. أوقفه من خيارات المطوّرين.",
        "developer_options.GOOD" to "خيارات المطوّرين متوقفة.",
        "developer_options.WARN" to "خيارات المطوّرين مُفعّلة. أوقفها إن لم تكن بحاجة إليها.",
        "developer_options.UNKNOWN" to "تعذّر التحقق من خيارات المطوّرين.",
        "root.GOOD" to "لا مؤشرات على أن الهاتف مُخترق الصلاحيات (روت).",
        "root.WARN" to "مؤشرات على أن الهاتف مُخترق الصلاحيات ({0}). الروت يزيل حماية أندرويد بين التطبيقات.",
        "unknown_sources.GOOD" to "لا يُسمح لأي تطبيق بتثبيت تطبيقات أخرى.",
        "unknown_sources.WARN" to "يُسمح لهذه التطبيقات بتثبيت تطبيقات أخرى: {0}. أوقف ذلك من الإعدادات ← التطبيقات ← الوصول الخاص ← تثبيت تطبيقات غير معروفة.",
    )

    private fun fill(template: String, args: List<String>): String =
        args.foldIndexed(template) { index, text, value -> text.replace("{$index}", value) }

    fun finding(finding: Finding, lang: Lang): String =
        fill((if (lang == Lang.AR) findingsAr else findingsEn)[finding.code] ?: finding.code, finding.args)

    fun check(check: DeviceCheck, lang: Lang): String =
        fill((if (lang == Lang.AR) checksAr else checksEn)["${check.code}.${check.status}"] ?: check.code, check.args)

    /** For tests: every key must exist in both languages. */
    internal fun keys() = listOf(findingsEn.keys to findingsAr.keys, checksEn.keys to checksAr.keys)
}

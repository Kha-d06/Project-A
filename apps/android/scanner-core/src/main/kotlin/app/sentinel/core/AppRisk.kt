package app.sentinel.core

/** What Android tells us about one installed app. Collected by the app module. */
data class AppInfo(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val isSystem: Boolean,
    /** Package that installed it (an app store), or null for adb, preinstalled or unknown. */
    val installer: String?,
    val targetSdk: Int,
    val requestedPermissions: Set<String>,
    /** Permissions that protect its services and receivers, e.g. BIND_ACCESSIBILITY_SERVICE. */
    val boundPermissions: Set<String>,
    val hasLauncherIcon: Boolean,
    val isDefaultSmsApp: Boolean = false,
    /** SHA-256 of base.apk, when it could be read. */
    val apkSha256: String? = null,
)

data class AppAssessment(val app: AppInfo, val verdict: Verdict, val findings: List<Finding>) {
    val needsAttention: Boolean get() = verdict == Verdict.MALICIOUS || verdict == Verdict.SUSPICIOUS
}

object AppRisk {
    /** Stores that review apps before publishing them. */
    val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", // Google Play
        "com.google.android.feedback", // Google Play on some older devices
        "com.amazon.venezia", // Amazon Appstore
        "com.sec.android.app.samsungapps", // Galaxy Store
        "com.huawei.appmarket", // AppGallery
        "com.xiaomi.mipicks", // Xiaomi GetApps
        "com.xiaomi.market",
        "com.heytap.market", // OPPO / OnePlus / realme
        "com.oppo.market",
        "org.fdroid.fdroid", // F-Droid
    )

    /**
     * Well-known apps and their only official package names. An app installed from
     * outside a store that calls itself one of these, under another package, is
     * imitating it. Kept to names whose packages are certain, to avoid false alarms.
     */
    val BRANDS: Map<String, Set<String>> = mapOf(
        "WhatsApp" to setOf("com.whatsapp", "com.whatsapp.w4b"),
        "Telegram" to setOf("org.telegram.messenger", "org.telegram.messenger.web", "org.thunderdog.challegram"),
        "Instagram" to setOf("com.instagram.android", "com.instagram.lite"),
        "Facebook" to setOf("com.facebook.katana", "com.facebook.lite"),
        "Messenger" to setOf("com.facebook.orca", "com.facebook.mlite"),
        "Signal" to setOf("org.thoughtcrime.securesms"),
        "Snapchat" to setOf("com.snapchat.android"),
        "TikTok" to setOf("com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "com.zhiliaoapp.musically.go"),
        "Google Play" to setOf("com.android.vending"),
        "Chrome" to setOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary"),
        "PayPal" to setOf("com.paypal.android.p2pmobile"),
        "Netflix" to setOf("com.netflix.mediaclient"),
    )

    private const val P = "android.permission."
    private val SMS = setOf("${P}READ_SMS", "${P}RECEIVE_SMS")
    private val LOCATION = setOf("${P}ACCESS_FINE_LOCATION", "${P}ACCESS_BACKGROUND_LOCATION")
    private val SPYING = setOf("${P}RECORD_AUDIO", "${P}READ_SMS", "${P}READ_CALL_LOG", "${P}READ_CONTACTS")

    fun sideloaded(app: AppInfo): Boolean = !app.isSystem && app.installer !in TRUSTED_INSTALLERS

    fun assess(app: AppInfo, knownMalware: Set<String>): AppAssessment {
        val findings = mutableListOf<Finding>()
        if (app.apkSha256 != null && app.apkSha256.lowercase() in knownMalware) {
            findings += Finding("known_malware", Verdict.MALICIOUS)
        }
        // Preinstalled apps come with the phone; only a known-malware match is reported for them.
        if (!app.isSystem) findings += behaviour(app)
        val verdict = Verdict.worst(findings.map { it.verdict })
        return AppAssessment(app, verdict, findings.sortedBy { it.verdict.ordinal })
    }

    private fun behaviour(app: AppInfo): List<Finding> {
        val findings = mutableListOf<Finding>()
        val outside = sideloaded(app)
        val requested = app.requestedPermissions
        val accessibility = "${P}BIND_ACCESSIBILITY_SERVICE" in app.boundPermissions
        val overlay = "${P}SYSTEM_ALERT_WINDOW" in requested

        imitatedBrand(app)?.let { brand -> if (outside) findings += Finding("imitates_brand", Verdict.SUSPICIOUS, listOf(brand)) }
        if (!outside) {
            if (app.targetSdk in 1..22) findings += Finding("old_target", Verdict.REVIEW)
            return findings
        }
        findings += Finding("sideloaded", Verdict.REVIEW)
        when {
            accessibility && overlay -> findings += Finding("accessibility_overlay", Verdict.SUSPICIOUS)
            accessibility -> findings += Finding("accessibility", Verdict.REVIEW)
        }
        if (requested.any { it in SMS } && !app.isDefaultSmsApp) findings += Finding("reads_sms", Verdict.SUSPICIOUS)
        if ("${P}BIND_DEVICE_ADMIN" in app.boundPermissions) findings += Finding("device_admin", Verdict.SUSPICIOUS)
        if ("${P}BIND_NOTIFICATION_LISTENER_SERVICE" in app.boundPermissions) findings += Finding("notification_listener", Verdict.REVIEW)
        if ("${P}REQUEST_INSTALL_PACKAGES" in requested) findings += Finding("installs_apps", Verdict.REVIEW)
        if (!app.hasLauncherIcon) {
            val watching = requested.any { it in LOCATION } && requested.any { it in SPYING }
            findings += if (watching) Finding("stalkerware", Verdict.SUSPICIOUS) else Finding("hidden_icon", Verdict.REVIEW)
        }
        if (app.targetSdk in 1..22) findings += Finding("old_target", Verdict.REVIEW)
        return findings
    }

    /** The brand this app's name claims, if it is not one of that brand's packages. */
    fun imitatedBrand(app: AppInfo): String? {
        val label = normalise(app.label)
        for ((brand, packages) in BRANDS) {
            if (app.packageName in packages) return null
            if (Regex("(^|[^a-z0-9])${Regex.escape(normalise(brand))}([^a-z0-9]|$)").containsMatchIn(label)) return brand
        }
        return null
    }

    /** Lower case, digits that stand in for letters replaced, invisible characters removed. */
    fun normalise(text: String): String =
        text.lowercase()
            .replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060\\uFEFF]"), "")
            .map { when (it) { '0' -> 'o'; '1' -> 'l'; '3' -> 'e'; '4' -> 'a'; '5' -> 's'; '@' -> 'a'; else -> it } }
            .joinToString("")
            .replace(Regex("\\s+"), " ")
            .trim()
}

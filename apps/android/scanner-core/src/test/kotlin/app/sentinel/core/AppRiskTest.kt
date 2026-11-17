package app.sentinel.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AppRiskTest {
    private val p = "android.permission."
    private fun app(
        pkg: String = "com.example.app",
        label: String = "Example",
        installer: String? = "com.android.vending",
        system: Boolean = false,
        requested: Set<String> = emptySet(),
        bound: Set<String> = emptySet(),
        launcher: Boolean = true,
        target: Int = 34,
        hash: String? = null,
        sms: Boolean = false,
    ) = AppInfo(pkg, label, "1.0", system, installer, target, requested, bound, launcher, sms, hash)

    private fun codes(a: AppAssessment) = a.findings.map { it.code }

    @Test
    fun `a store app with ordinary permissions has nothing to report`() {
        val result = AppRisk.assess(app(requested = setOf("${p}INTERNET", "${p}CAMERA")), emptySet())
        assertEquals(Verdict.NO_KNOWN_THREAT, result.verdict)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `known malware is malicious wherever it came from, even preinstalled`() {
        val hash = "a".repeat(64)
        assertEquals(Verdict.MALICIOUS, AppRisk.assess(app(hash = hash.uppercase()), setOf(hash)).verdict)
        val system = AppRisk.assess(app(system = true, installer = null, hash = hash, requested = setOf("${p}READ_SMS")), setOf(hash))
        assertEquals(listOf("known_malware"), codes(system))
    }

    @Test
    fun `banking trojan pattern from outside a store is suspicious`() {
        val trojan = app(
            pkg = "com.update.service.sys",
            label = "System Update",
            installer = "com.google.android.packageinstaller",
            requested = setOf("${p}SYSTEM_ALERT_WINDOW", "${p}RECEIVE_SMS", "${p}INTERNET"),
            bound = setOf("${p}BIND_ACCESSIBILITY_SERVICE", "${p}BIND_DEVICE_ADMIN"),
        )
        val result = AppRisk.assess(trojan, emptySet())
        assertEquals(Verdict.SUSPICIOUS, result.verdict)
        assertTrue(codes(result).containsAll(listOf("accessibility_overlay", "reads_sms", "device_admin", "sideloaded")))
        // Store apps with the same permissions are not flagged: the store reviews them.
        assertEquals(Verdict.NO_KNOWN_THREAT, AppRisk.assess(trojan.copy(installer = "com.android.vending"), emptySet()).verdict)
    }

    @Test
    fun `fake WhatsApp is caught, real one and store add-ons are not`() {
        val fake = AppRisk.assess(app(pkg = "com.whatsapp.plus", label = "WhatsApp Plus", installer = null), emptySet())
        assertEquals(Verdict.SUSPICIOUS, fake.verdict)
        assertEquals(listOf("WhatsApp"), fake.findings.first { it.code == "imitates_brand" }.args)
        assertNull(AppRisk.imitatedBrand(app(pkg = "com.whatsapp", label = "WhatsApp")))
        assertEquals(Verdict.NO_KNOWN_THREAT, AppRisk.assess(app(pkg = "com.stickers.wa", label = "Stickers for WhatsApp"), emptySet()).verdict)
        // Lookalike spellings and invisible characters do not hide the brand.
        assertEquals("Telegram", AppRisk.imitatedBrand(app(pkg = "org.tele.gram", label = "Te​legr4m")))
        assertNull(AppRisk.imitatedBrand(app(pkg = "com.chromecast.helper", label = "Chromecast helper")))
    }

    @Test
    fun `hidden app watching location and messages looks like stalkerware`() {
        val spy = app(
            installer = null,
            launcher = false,
            requested = setOf("${p}ACCESS_BACKGROUND_LOCATION", "${p}READ_CALL_LOG", "${p}RECORD_AUDIO"),
        )
        assertTrue("stalkerware" in codes(AppRisk.assess(spy, emptySet())))
        assertEquals(listOf("sideloaded", "hidden_icon"), codes(AppRisk.assess(app(installer = null, launcher = false), emptySet())))
    }

    @Test
    fun `default SMS app may read messages`() {
        val messages = app(installer = "org.fdroid.fdroid", requested = setOf("${p}READ_SMS"), sms = true)
        assertEquals(Verdict.NO_KNOWN_THREAT, AppRisk.assess(messages, emptySet()).verdict)
        val other = app(installer = null, requested = setOf("${p}READ_SMS"))
        assertTrue("reads_sms" in codes(AppRisk.assess(other, emptySet())))
    }

    @Test
    fun `old target SDK is worth a review`() {
        assertEquals(listOf("old_target"), codes(AppRisk.assess(app(target = 22), emptySet())))
    }
}

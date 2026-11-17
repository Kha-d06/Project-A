package app.sentinel.core

import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeviceChecksTest {
    private val today = LocalDate.parse("2026-11-17")
    private fun facts(patch: String? = "2026-11-01", lock: Boolean? = true, dev: Boolean? = false, adb: Boolean? = false, root: List<String> = emptyList(), installers: List<String> = emptyList()) =
        DeviceFacts("16", 36, patch, lock, dev, adb, root, installers)

    private fun status(checks: List<DeviceCheck>, code: String) = checks.first { it.code == code }.status

    @Test
    fun `a well-kept phone passes`() {
        assertTrue(DeviceChecks.assess(facts(), today).all { it.status == CheckStatus.GOOD })
    }

    @Test
    fun `old patches, no lock, debugging, root and install permissions are reported`() {
        val checks = DeviceChecks.assess(facts(patch = "2026-03-05", lock = false, dev = true, adb = true, root = listOf("/system/xbin/su"), installers = listOf("Files")), today)
        assertEquals(CheckStatus.BAD, status(checks, "patch"))
        assertEquals(listOf("2026-03-05", "8"), checks.first { it.code == "patch" }.args)
        assertEquals(CheckStatus.BAD, status(checks, "screen_lock"))
        assertEquals(CheckStatus.BAD, status(checks, "usb_debugging"))
        assertEquals(CheckStatus.WARN, status(checks, "root"))
        assertEquals(CheckStatus.WARN, status(checks, "unknown_sources"))
        assertEquals(CheckStatus.WARN, status(DeviceChecks.assess(facts(patch = "2026-07-01"), today), "patch"))
        assertEquals(CheckStatus.UNKNOWN, status(DeviceChecks.assess(facts(patch = "garbage", lock = null), today), "patch"))
    }

    @Test
    fun `summary for the website holds only these values`() {
        assertEquals(
            mapOf("os" to "Android 16", "patch_age_days" to 16L, "screen_lock" to true, "developer_options" to false, "unknown_sources" to 0),
            DeviceChecks.summary(facts(), today),
        )
    }
}

class FileChecksTest {
    private fun check(name: String, bytes: ByteArray, bad: Set<String> = emptySet()) = FileChecks.assess(name, bytes.inputStream(), bad)
    private val apk = byteArrayOf(0x50, 0x4B, 0x03, 0x04) + ByteArray(30) + "AndroidManifest.xml".toByteArray() + ByteArray(100)

    @Test
    fun `EICAR and known hashes are malicious`() {
        val eicar = check("eicar.com", FileChecks.EICAR.toByteArray())
        assertEquals(Verdict.MALICIOUS, eicar.verdict)
        assertEquals("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", eicar.sha256)
        val sample = "sample".toByteArray()
        val hash = check("x.bin", sample).sha256
        assertEquals(listOf("known_malware"), check("x.bin", sample, setOf(hash)).findings.map { it.code })
    }

    @Test
    fun `app installers are flagged for review, disguised ones as suspicious`() {
        assertEquals(listOf("app_installer"), check("game.apk", apk).findings.map { it.code })
        assertEquals(Verdict.SUSPICIOUS, check("invoice.pdf.apk", apk).verdict)
        assertEquals(listOf("disguised_program", "app_installer"), check("photo.jpg", apk).findings.map { it.code })
        assertEquals(Verdict.SUSPICIOUS, check("documents.zip", apk).verdict)
        assertEquals(Verdict.NO_KNOWN_THREAT, check("notes.txt", "milk, bread".toByteArray()).verdict)
        assertEquals(Verdict.NO_KNOWN_THREAT, check("photos.zip", byteArrayOf(0x50, 0x4B, 0x03, 0x04) + ByteArray(200)).verdict)
    }

    @Test
    fun `large files are hashed completely`() {
        val big = ByteArray(3 * 1024 * 1024 + 7) { (it % 251).toByte() }
        val expected = java.security.MessageDigest.getInstance("SHA-256").digest(big).joinToString("") { "%02x".format(it) }
        val result = check("video.mp4", big)
        assertEquals(expected, result.sha256)
        assertEquals(big.size.toLong(), result.size)
    }
}

class MessagesTest {
    @Test
    fun `every message exists in English and Arabic and fills in values`() {
        Messages.keys().forEach { (en, ar) -> assertEquals(en, ar) }
        assertEquals(
            "Calls itself WhatsApp, but is not the official WhatsApp app and was not installed from an app store.",
            Messages.finding(Finding("imitates_brand", Verdict.SUSPICIOUS, listOf("WhatsApp")), Messages.Lang.EN),
        )
        assertTrue(Messages.check(DeviceCheck("patch", CheckStatus.BAD, listOf("2026-03-05", "8")), Messages.Lang.AR).contains("8 أشهر"))
    }
}

class StringsTest {
    @Test
    fun `interface text exists in both languages and formats numbers`() {
        val (en, ar) = Strings.keys()
        assertEquals(en, ar)
        assertEquals("3 app(s) or file(s) need your attention.", Strings.format(Messages.Lang.EN, "notify_body", 3))
    }
}

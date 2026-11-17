package app.sentinel.core

import java.io.InputStream
import java.security.MessageDigest

data class FileAssessment(
    val name: String,
    val sha256: String,
    val size: Long,
    val verdict: Verdict,
    val findings: List<Finding>,
)

object FileChecks {
    const val EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"
    private const val HEAD_BYTES = 1024 * 1024
    private val APP_EXTENSIONS = setOf("apk", "xapk", "apks", "apkm")
    private val HARMLESS_LOOKING = setOf("pdf", "jpg", "jpeg", "png", "gif", "webp", "mp4", "mp3", "doc", "docx", "xls", "xlsx", "txt", "zip")

    private fun extension(name: String): String = name.substringAfterLast('.', "").lowercase()

    /** "invoice.pdf.apk": the name shows a harmless type but the real extension is another. */
    private fun doubleExtension(name: String): Boolean {
        val parts = name.lowercase().split('.')
        return parts.size >= 3 && parts[parts.size - 2] in HARMLESS_LOOKING && parts.last() !in HARMLESS_LOOKING
    }

    private fun startsWith(head: ByteArray, prefix: ByteArray) = head.size >= prefix.size && prefix.indices.all { head[it] == prefix[it] }

    private fun contains(head: ByteArray, needle: ByteArray): Boolean {
        outer@ for (i in 0..head.size - needle.size) {
            for (j in needle.indices) if (head[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    /** Reads the stream once: hashes all of it and keeps the first megabyte for content checks. */
    fun assess(name: String, input: InputStream, knownMalware: Set<String>): FileAssessment {
        val digest = MessageDigest.getInstance("SHA-256")
        val head = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        var size = 0L
        input.use { stream ->
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
                if (head.size() < HEAD_BYTES) head.write(buffer, 0, minOf(read, HEAD_BYTES - head.size()))
                size += read
            }
        }
        val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
        val bytes = head.toByteArray()
        val findings = mutableListOf<Finding>()

        if (sha256 in knownMalware) findings += Finding("known_malware", Verdict.MALICIOUS)
        if (size < 256 && String(bytes, Charsets.ISO_8859_1).trimEnd().startsWith(EICAR)) findings += Finding("eicar", Verdict.MALICIOUS)

        val zip = startsWith(bytes, byteArrayOf(0x50, 0x4B, 0x03, 0x04))
        val androidApp = zip && (extension(name) in APP_EXTENSIONS || contains(bytes, "AndroidManifest.xml".toByteArray()))
        val windowsProgram = startsWith(bytes, "MZ".toByteArray())
        val linuxProgram = startsWith(bytes, byteArrayOf(0x7F, 0x45, 0x4C, 0x46))
        val ext = extension(name)
        when {
            doubleExtension(name) -> findings += Finding("double_extension", Verdict.SUSPICIOUS)
            (androidApp || windowsProgram || linuxProgram) && ext in HARMLESS_LOOKING && ext != "zip" ->
                findings += Finding("disguised_program", Verdict.SUSPICIOUS)
            androidApp && ext == "zip" -> findings += Finding("disguised_program", Verdict.SUSPICIOUS)
        }
        if (androidApp) findings += Finding("app_installer", Verdict.REVIEW)

        return FileAssessment(name, sha256, size, Verdict.worst(findings.map { it.verdict }), findings.sortedBy { it.verdict.ordinal })
    }
}

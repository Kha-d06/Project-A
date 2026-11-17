package app.sentinel.protect

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import app.sentinel.core.Account
import app.sentinel.core.AppAssessment
import app.sentinel.core.AppRisk
import app.sentinel.core.DeviceCheck
import app.sentinel.core.DeviceChecks
import app.sentinel.core.Detection
import app.sentinel.core.FileAssessment
import app.sentinel.core.FileChecks
import app.sentinel.core.HashList
import app.sentinel.core.HttpResponse
import app.sentinel.core.Messages
import app.sentinel.core.Strings
import app.sentinel.core.Protocol
import app.sentinel.core.RemoteAgent
import app.sentinel.core.RemoteHost
import app.sentinel.core.ScanOutcome
import app.sentinel.core.Transport
import app.sentinel.core.Verdict
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.util.Locale
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class FileResult(val path: String, val assessment: FileAssessment)

data class ScanReport(
    val at: Long,
    val apps: List<AppAssessment>,
    val files: List<FileResult>,
    val checks: List<DeviceCheck>,
    val filesSkipped: Boolean,
) {
    val appsNeedingAttention get() = apps.filter { it.needsAttention }
    val filesNeedingAttention get() = files.filter { it.assessment.verdict == Verdict.MALICIOUS || it.assessment.verdict == Verdict.SUSPICIOUS }
}

data class QuarantinedFile(val id: String, val originalPath: String, val name: String, val sha256: String, val at: Long)

/** HTTP for the core protocol, with timeouts and no redirects to other hosts. */
object HttpTransport : Transport {
    override fun send(method: String, url: String, body: String?, token: String?): HttpResponse {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "application/json")
            if (token != null) connection.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toByteArray()) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            return HttpResponse(status, stream?.bufferedReader()?.use { it.readText() } ?: "")
        } finally {
            connection.disconnect()
        }
    }
}

/**
 * Everything the screens and the background check-in share. One instance per
 * process; scans run one at a time.
 */
class Engine private constructor(private val context: Context) : RemoteHost {
    companion object {
        @Volatile private var instance: Engine? = null
        fun get(context: Context): Engine = instance ?: synchronized(this) { instance ?: Engine(context.applicationContext).also { instance = it } }

        private const val MAX_FILES = 20_000
        private const val MAX_FILE_BYTES = 512L * 1024 * 1024
        private const val CHANNEL = "alerts"
        private val SKIP_DIRS = setOf("Android", ".thumbnails", ".trash", ".Trash")
    }

    private val prefs = context.getSharedPreferences("sentinel", Context.MODE_PRIVATE)
    private val hashFile = File(context.filesDir, "hash-list.json")
    private val quarantineDir = File(context.filesDir, "quarantine").apply { mkdirs() }
    private val lock = Any()
    @Volatile var lastReport: ScanReport? = null
        private set
    @Volatile var lastCheckInError: String? = null
        private set

    val lang: Messages.Lang get() = if (Locale.getDefault().language == "ar") Messages.Lang.AR else Messages.Lang.EN

    // --- Settings ----------------------------------------------------------------

    var serverUrl: String
        get() = prefs.getString("server", null) ?: BuildConfig.SITE_URL
        set(value) = prefs.edit().putString("server", value.trimEnd('/')).apply()

    var account: Account?
        get() {
            val token = prefs.getString("token", null) ?: return null
            return Account(prefs.getString("account_server", serverUrl)!!, prefs.getString("device_id", "")!!, token, prefs.getString("email", "")!!)
        }
        set(value) {
            prefs.edit().apply {
                if (value == null) {
                    remove("token"); remove("device_id"); remove("email"); remove("account_server"); putBoolean("allow_remote", false)
                } else {
                    putString("token", value.token); putString("device_id", value.deviceId); putString("email", value.email); putString("account_server", value.server)
                }
            }.apply()
        }

    var remoteAllowed: Boolean
        get() = prefs.getBoolean("allow_remote", false)
        set(value) = prefs.edit().putBoolean("allow_remote", value).apply()

    val deviceName: String get() = "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}".take(80)

    // --- Signatures ----------------------------------------------------------------

    private var knownMalware: Set<String> = runCatching { HashList.parse(hashFile.readText()) }.getOrDefault(emptySet())
    val signatureCount: Int get() = knownMalware.size

    override fun updateSignatures() {
        val response = HttpTransport.send("GET", Protocol.api(serverUrl, "/intelligence/hash-list"), null, null)
        if (response.status != 200) throw IllegalStateException("The server answered ${response.status}")
        knownMalware = HashList.parse(response.body)
        hashFile.writeText(response.body)
        prefs.edit().putLong("signatures_at", System.currentTimeMillis()).apply()
    }

    fun signaturesAge(): Long = System.currentTimeMillis() - prefs.getLong("signatures_at", 0)

    // --- Storage access --------------------------------------------------------------

    fun hasFileAccess(): Boolean =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    @Suppress("DEPRECATION")
    private fun downloads(): File = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)

    @Suppress("DEPRECATION")
    private fun storageRoot(): File = Environment.getExternalStorageDirectory()

    private fun walk(root: File): Sequence<File> =
        root.walkTopDown()
            .onEnter { dir -> dir == root || (dir.name !in SKIP_DIRS && !dir.name.startsWith(".")) }
            .filter { it.isFile && it.length() <= MAX_FILE_BYTES }
            .take(MAX_FILES)

    private fun scanFiles(root: File, progress: (String) -> Unit): List<FileResult> =
        walk(root).mapNotNull { file ->
            progress(file.name)
            runCatching { FileResult(file.absolutePath, FileChecks.assess(file.name, file.inputStream(), knownMalware)) }.getOrNull()
        }.toList()

    /** Files the person picked with the system file picker (no storage permission needed). */
    fun scanPicked(uris: List<Uri>): List<FileResult> = uris.mapNotNull { uri ->
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: "file"
        runCatching {
            context.contentResolver.openInputStream(uri)?.let { FileResult(uri.toString(), FileChecks.assess(name, it, knownMalware)) }
        }.getOrNull()
    }

    // --- Scanning -------------------------------------------------------------------

    /** Apps, device settings and, with file access, Downloads (quick) or all shared storage (full). */
    fun scan(full: Boolean, progress: (String) -> Unit = {}): ScanReport = synchronized(lock) {
        if (signaturesAge() > 24 * 3600_000L) runCatching { updateSignatures() }
        progress("apps")
        val apps = Inventory.apps(context) { done, total -> progress("apps $done/$total") }.map { AppRisk.assess(it, knownMalware) }
        val checks = DeviceChecks.assess(Inventory.deviceFacts(context))
        val access = hasFileAccess()
        val files = if (access) scanFiles(if (full) storageRoot() else downloads(), progress) else emptyList()
        val report = ScanReport(System.currentTimeMillis(), apps, files, checks, filesSkipped = !access)
        lastReport = report
        prefs.edit().putLong("last_scan", report.at).putInt("last_threats", report.appsNeedingAttention.size + report.filesNeedingAttention.size).apply()
        notifyIfNeeded(report)
        report
    }

    private fun outcome(report: ScanReport): ScanOutcome {
        val appDetections = report.appsNeedingAttention.map { result ->
            Detection(
                name = "${result.app.label} (${result.app.packageName})",
                folder = "Installed apps",
                verdict = result.verdict,
                title = result.findings.firstOrNull()?.let { Messages.finding(it, Messages.Lang.EN) } ?: "",
                sha256 = null,
            )
        }
        val fileDetections = report.filesNeedingAttention.map { result ->
            Detection(
                name = result.assessment.name,
                folder = File(result.path).parentFile?.name,
                verdict = result.assessment.verdict,
                title = result.assessment.findings.firstOrNull()?.let { Messages.finding(it, Messages.Lang.EN) } ?: "",
                sha256 = result.assessment.sha256,
            )
        }
        val all = appDetections + fileDetections
        return ScanOutcome(
            scanned = report.apps.size + report.files.size,
            malicious = all.count { it.verdict == Verdict.MALICIOUS },
            suspicious = all.count { it.verdict == Verdict.SUSPICIOUS },
            quarantined = 0,
            detections = all,
        )
    }

    // --- Quarantine ------------------------------------------------------------------

    /**
     * Encrypts the file into the app's private folder (AES-256-GCM, random key kept
     * beside it) and deletes the original, so it can no longer be opened or installed.
     */
    fun quarantineFile(path: String, sha256: String): Boolean {
        val file = File(path)
        if (!file.isFile || !hasFileAccess()) return false
        if (Inventory.sha256(file) != sha256) return false
        val id = UUID.randomUUID().toString()
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)) }
        file.inputStream().use { input -> CipherOutputStream(File(quarantineDir, "$id.bin").outputStream(), cipher).use { input.copyTo(it) } }
        File(quarantineDir, "$id.json").writeText(
            JSONObject()
                .put("path", file.absolutePath).put("name", file.name).put("sha256", sha256).put("at", System.currentTimeMillis())
                .put("key", android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP))
                .put("iv", android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP))
                .toString(),
        )
        if (!file.delete()) {
            File(quarantineDir, "$id.bin").delete(); File(quarantineDir, "$id.json").delete()
            return false
        }
        return true
    }

    fun quarantined(): List<QuarantinedFile> =
        quarantineDir.listFiles { f -> f.name.endsWith(".json") }.orEmpty().mapNotNull { meta ->
            runCatching {
                val json = JSONObject(meta.readText())
                QuarantinedFile(meta.name.removeSuffix(".json"), json.getString("path"), json.getString("name"), json.getString("sha256"), json.getLong("at"))
            }.getOrNull()
        }.sortedByDescending { it.at }

    fun restore(id: String): Boolean {
        val meta = File(quarantineDir, "$id.json")
        val data = File(quarantineDir, "$id.bin")
        val json = runCatching { JSONObject(meta.readText()) }.getOrNull() ?: return false
        var target = File(json.getString("path"))
        if (target.exists()) target = File(target.parentFile, "restored-${target.name}")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(android.util.Base64.decode(json.getString("key"), android.util.Base64.NO_WRAP), "AES"),
                GCMParameterSpec(128, android.util.Base64.decode(json.getString("iv"), android.util.Base64.NO_WRAP)),
            )
        }
        target.parentFile?.mkdirs()
        val partial = File(target.parentFile, ".${target.name}.restoring")
        try {
            CipherInputStream(data.inputStream(), cipher).use { input -> partial.outputStream().use { input.copyTo(it) } }
        } catch (error: Exception) {
            partial.delete()
            return false
        }
        if (!partial.renameTo(target)) return false
        return meta.delete() && data.delete()
    }

    fun deleteQuarantined(id: String): Boolean = File(quarantineDir, "$id.bin").delete() and File(quarantineDir, "$id.json").delete()

    // --- Notifications ---------------------------------------------------------------

    private fun notifyIfNeeded(report: ScanReport) {
        val count = report.appsNeedingAttention.size + report.filesNeedingAttention.size
        if (count == 0) return
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(NotificationChannel(CHANNEL, Strings.get(lang, "channel"), NotificationManager.IMPORTANCE_HIGH))
        val open = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(Strings.get(lang, "notify_title"))
            .setContentText(Strings.format(lang, "notify_body", count))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        manager.notify(1, notification)
    }

    // --- Remote commands (RemoteHost) ----------------------------------------------------

    fun checkIn() {
        val linked = account ?: return
        val agent = RemoteAgent(this, HttpTransport)
        agent.checkIn(linked)
        lastCheckInError = agent.lastError
        prefs.edit().putLong("last_check_in", System.currentTimeMillis()).apply()
    }

    fun lastCheckIn(): Long = prefs.getLong("last_check_in", 0)

    override fun allowRemote(): Boolean = remoteAllowed

    override fun folders(): List<Pair<String, String>> = if (hasFileAccess()) listOf("downloads" to "Download") else emptyList()

    override fun status(): Map<String, Any?> {
        val facts = Inventory.deviceFacts(context)
        val report = lastReport
        return DeviceChecks.summary(facts) + mapOf(
            "signatures" to signatureCount,
            "file_access" to hasFileAccess(),
            "risky_apps" to report?.appsNeedingAttention?.size,
        )
    }

    override fun version(): String = BuildConfig.VERSION_NAME

    override fun quickScan(): ScanOutcome = outcome(scan(full = false))

    override fun fullScan(): ScanOutcome = outcome(scan(full = true))

    override fun folderScan(folderId: String): ScanOutcome? =
        if (folderId == "downloads" && hasFileAccess()) outcome(scan(full = false)) else null

    override fun quarantine(sha256: List<String>): Int {
        val wanted = sha256.toSet()
        return lastReport?.files.orEmpty()
            .filter { it.assessment.sha256 in wanted }
            .distinctBy { it.path }
            .count { quarantineFile(it.path, it.assessment.sha256) }
    }

    override fun unlinked() {
        account = null
    }

    override fun activity(message: String) {}

    fun link(code: String) {
        val linked = Protocol.register(HttpTransport, serverUrl, code, deviceName, BuildConfig.VERSION_NAME)
        account = linked
        CheckInJob.schedule(context)
    }

    fun unlink() {
        val linked = account ?: return
        runCatching { HttpTransport.send("DELETE", Protocol.api(linked.server, "/devices/self"), null, linked.token) }
        account = null
    }
}

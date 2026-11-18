package app.sentinel.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Linking the phone to a Qalaa account and running scans started from the
 * website. The same protocol as Qalaa Desktop:
 * - nothing runs unless the person turned on "Allow scans from my account" in the app;
 * - folders are offered by id and label only, never by path;
 * - results carry names, verdicts and fingerprints, never file contents.
 */
data class Account(val server: String, val deviceId: String, val token: String, val email: String)

data class HttpResponse(val status: Int, val body: String)

/** HTTP is done by the app module (HttpURLConnection), and by a fake in tests. */
fun interface Transport {
    fun send(method: String, url: String, body: String?, token: String?): HttpResponse
}

class RemoteError(message: String, val status: Int) : Exception(message)

data class Detection(
    val name: String,
    val folder: String?,
    val verdict: Verdict,
    val title: String,
    /** Null for installed apps: they cannot be quarantined, only uninstalled on the phone. */
    val sha256: String?,
    val quarantined: Boolean = false,
)

data class ScanOutcome(
    val scanned: Int,
    val malicious: Int,
    val suspicious: Int,
    val quarantined: Int,
    val detections: List<Detection>,
)

data class RemoteCommand(val id: String, val kind: String, val folderId: String?, val sha256: List<String>)

interface RemoteHost {
    fun allowRemote(): Boolean
    /** (id, label) pairs. */
    fun folders(): List<Pair<String, String>>
    fun status(): Map<String, Any?>
    fun version(): String
    fun quickScan(): ScanOutcome
    fun fullScan(): ScanOutcome
    fun folderScan(folderId: String): ScanOutcome?
    fun quarantine(sha256: List<String>): Int
    fun updateSignatures()
    fun unlinked()
    fun activity(message: String)
}

object Protocol {
    private const val MAX_DETECTIONS = 200
    private val HASH = Regex("^[0-9a-f]{64}$")

    fun api(server: String, path: String) = "${server.trimEnd('/')}/api/v1$path"

    private fun check(response: HttpResponse): HttpResponse {
        if (response.status in 200..299) return response
        val message = runCatching { JSONObject(response.body).getJSONObject("error").getString("message") }
            .getOrDefault("The server answered ${response.status}")
        throw RemoteError(message, response.status)
    }

    fun register(transport: Transport, server: String, code: String, name: String, version: String): Account {
        val body = JSONObject()
            .put("link_code", code.trim())
            .put("name", name.take(80))
            .put("platform", "android")
            .put("app_version", version.take(20))
        val reply = JSONObject(check(transport.send("POST", api(server, "/devices/register"), body.toString(), null)).body)
        return Account(server, reply.getString("device_id"), reply.getString("token"), reply.getString("account_email"))
    }

    fun heartbeatBody(host: RemoteHost): String {
        val folders = JSONArray()
        host.folders().forEach { (id, label) -> folders.put(JSONObject().put("id", id).put("label", label)) }
        val status = JSONObject()
        host.status().forEach { (key, value) ->
            status.put(key, when (value) {
                null -> JSONObject.NULL
                is Number, is Boolean, is String -> value
                else -> value.toString()
            })
        }
        return JSONObject()
            .put("allow_remote", host.allowRemote())
            .put("folders", folders)
            .put("status", status)
            .put("app_version", host.version())
            .toString()
    }

    fun parseCommands(body: String): List<RemoteCommand> {
        val array = JSONArray(body)
        return (0 until array.length()).map { index ->
            val item = array.getJSONObject(index)
            val args = item.optJSONObject("args") ?: JSONObject()
            val hashes = args.optJSONArray("sha256")
            RemoteCommand(
                id = item.getString("id"),
                kind = item.getString("kind"),
                folderId = args.optString("folder_id").ifEmpty { null },
                sha256 = if (hashes == null) emptyList() else (0 until hashes.length()).map { hashes.getString(it) }.filter { HASH.matches(it) },
            )
        }
    }

    fun resultBody(outcome: ScanOutcome?, ok: Boolean, error: String? = null, quarantined: Int? = null, seconds: Long = 0): String {
        val json = JSONObject().put("ok", ok).put("duration_seconds", seconds)
        if (error != null) json.put("error", error.take(300))
        if (outcome != null) {
            val detections = JSONArray()
            outcome.detections.take(MAX_DETECTIONS).forEach { d ->
                detections.put(
                    JSONObject()
                        .put("name", d.name.take(255))
                        .put("folder", d.folder?.take(80) ?: JSONObject.NULL)
                        .put("verdict", d.verdict.wire)
                        .put("title", d.title.take(300))
                        .put("sha256", d.sha256 ?: JSONObject.NULL)
                        .put("quarantined", d.quarantined),
                )
            }
            json.put("scanned", outcome.scanned).put("malicious", outcome.malicious).put("suspicious", outcome.suspicious)
                .put("quarantined", outcome.quarantined).put("detections", detections)
        }
        if (quarantined != null) json.put("quarantined", quarantined)
        return json.toString()
    }
}

/** One check-in: heartbeat, then any waiting commands, one at a time. */
class RemoteAgent(private val host: RemoteHost, private val transport: Transport, private val clock: () -> Long = System::currentTimeMillis) {
    var lastError: String? = null
        private set

    fun checkIn(account: Account) {
        try {
            val beat = JSONObject(send(account, "POST", "/devices/heartbeat", Protocol.heartbeatBody(host)).body)
            lastError = null
            if (beat.optInt("pending_commands") > 0) {
                Protocol.parseCommands(send(account, "GET", "/devices/commands", null).body).forEach { run(account, it) }
            }
        } catch (error: RemoteError) {
            if (error.status == 401) {
                host.unlinked()
                lastError = "This phone was removed from your Qalaa account."
            } else {
                lastError = error.message
            }
        } catch (error: Exception) {
            lastError = error.message ?: error.toString()
        }
    }

    private fun send(account: Account, method: String, path: String, body: String?): HttpResponse =
        transport.send(method, Protocol.api(account.server, path), body, account.token).let {
            if (it.status in 200..299) it else throw RemoteError(
                runCatching { JSONObject(it.body).getJSONObject("error").getString("message") }.getOrDefault("The server answered ${it.status}"),
                it.status,
            )
        }

    private fun run(account: Account, command: RemoteCommand) {
        val result = "/devices/commands/${command.id}/result"
        if (!host.allowRemote()) {
            send(account, "POST", result, Protocol.resultBody(null, ok = false, error = "Remote scans are turned off on this phone."))
            return
        }
        send(account, "POST", "/devices/commands/${command.id}/started", null)
        val started = clock()
        val body = try {
            val seconds = { (clock() - started) / 1000 }
            when (command.kind) {
                "quick_scan" -> host.activity("quick_scan").let { Protocol.resultBody(host.quickScan(), ok = true, seconds = seconds()) }
                "full_scan" -> host.activity("full_scan").let { Protocol.resultBody(host.fullScan(), ok = true, seconds = seconds()) }
                "folder_scan" -> {
                    val outcome = command.folderId?.let { host.folderScan(it) }
                    if (outcome == null) Protocol.resultBody(null, ok = false, error = "That folder is no longer offered by this phone.")
                    else Protocol.resultBody(outcome, ok = true, seconds = seconds())
                }
                "quarantine" -> Protocol.resultBody(null, ok = true, quarantined = host.quarantine(command.sha256), seconds = seconds())
                "update_signatures" -> { host.updateSignatures(); Protocol.resultBody(null, ok = true, seconds = seconds()) }
                else -> Protocol.resultBody(null, ok = false, error = "This version of the app does not support that command.")
            }
        } catch (error: Exception) {
            Protocol.resultBody(null, ok = false, error = error.message ?: error.toString())
        }
        send(account, "POST", result, body)
    }
}

/** The server's list of known-malware fingerprints (GET /intelligence/hash-list). */
object HashList {
    fun parse(body: String): Set<String> {
        val array = JSONObject(body).getJSONArray("sha256")
        return (0 until array.length()).map { array.getString(it).lowercase() }.filter { it.length == 64 }.toSet()
    }
}

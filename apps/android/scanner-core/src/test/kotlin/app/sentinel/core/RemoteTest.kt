package app.sentinel.core

import org.json.JSONArray
import org.json.JSONObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RemoteTest {
    private val account = Account("https://sentinel.test", "d1", "sdv_x", "a@example.com")

    private class FakeServer(val commands: MutableList<JSONObject>) : Transport {
        val calls = mutableListOf<Triple<String, String, String?>>()
        val tokens = mutableListOf<String?>()
        var status = 200
        override fun send(method: String, url: String, body: String?, token: String?): HttpResponse {
            val path = url.removePrefix("https://sentinel.test/api/v1")
            calls += Triple(method, path, body)
            tokens += token
            if (status != 200) return HttpResponse(status, """{"error":{"message":"Unknown device"}}""")
            return when (path) {
                "/devices/heartbeat" -> HttpResponse(200, """{"pending_commands":${commands.size}}""")
                "/devices/commands" -> HttpResponse(200, JSONArray(commands.toList()).toString()).also { commands.clear() }
                "/devices/register" -> HttpResponse(201, """{"device_id":"d9","token":"sdv_new","account_email":"me@example.com"}""")
                else -> HttpResponse(204, "")
            }
        }
    }

    private class Host(var allow: Boolean = true) : RemoteHost {
        val log = mutableListOf<String>()
        var unlinked = false
        private val outcome = ScanOutcome(
            40, 1, 1, 0,
            listOf(
                Detection("Fake WhatsApp (com.whatsapp.plus)", "Installed apps", Verdict.SUSPICIOUS, "Calls itself WhatsApp", null),
                Detection("invoice.pdf.apk", "Download", Verdict.MALICIOUS, "Known malware", "b".repeat(64)),
            ),
        )
        override fun allowRemote() = allow
        override fun folders() = listOf("downloads" to "Download")
        override fun status() = mapOf<String, Any?>("os" to "Android 16", "screen_lock" to true, "patch_age_days" to null)
        override fun version() = "1.0.0"
        override fun quickScan() = outcome.also { log += "quick" }
        override fun fullScan() = outcome.also { log += "full" }
        override fun folderScan(folderId: String) = if (folderId == "downloads") outcome.also { log += "folder" } else null
        override fun quarantine(sha256: List<String>) = sha256.size.also { log += "quarantine:$sha256" }
        override fun updateSignatures() { log += "signatures" }
        override fun unlinked() { unlinked = true }
        override fun activity(message: String) {}
    }

    @Test
    fun `heartbeat sends labels and summary, never paths`() {
        val server = FakeServer(mutableListOf())
        RemoteAgent(Host(), server).checkIn(account)
        val beat = JSONObject(server.calls.single().third)
        assertTrue(beat.getBoolean("allow_remote"))
        assertEquals("Download", beat.getJSONArray("folders").getJSONObject(0).getString("label"))
        assertTrue(beat.getJSONObject("status").isNull("patch_age_days"))
        assertEquals("sdv_x", server.tokens.single())
    }

    @Test
    fun `runs commands in order and reports results`() {
        val host = Host()
        val server = FakeServer(mutableListOf(
            JSONObject("""{"id":"c1","kind":"folder_scan","args":{"folder_id":"downloads"}}"""),
            JSONObject("""{"id":"c2","kind":"quarantine","args":{"sha256":["${"b".repeat(64)}","nope"]}}"""),
            JSONObject("""{"id":"c3","kind":"folder_scan","args":{"folder_id":"../etc"}}"""),
            JSONObject("""{"id":"c4","kind":"update_signatures","args":{}}"""),
        ))
        RemoteAgent(host, server).checkIn(account)
        assertEquals(listOf("folder", "quarantine:[${"b".repeat(64)}]", "signatures"), host.log)
        val results = server.calls.filter { it.second.endsWith("/result") }.associate { it.second to JSONObject(it.third!!) }
        val scan = results.getValue("/devices/commands/c1/result")
        assertTrue(scan.getBoolean("ok"))
        assertEquals(2, scan.getJSONArray("detections").length())
        assertTrue(scan.getJSONArray("detections").getJSONObject(0).isNull("sha256"), "apps cannot be quarantined remotely")
        assertEquals(1, results.getValue("/devices/commands/c2/result").getInt("quarantined"))
        assertFalse(results.getValue("/devices/commands/c3/result").getBoolean("ok"))
    }

    @Test
    fun `nothing runs when remote scans are off`() {
        val host = Host(allow = false)
        val server = FakeServer(mutableListOf(JSONObject("""{"id":"c1","kind":"full_scan","args":{}}""")))
        RemoteAgent(host, server).checkIn(account)
        assertTrue(host.log.isEmpty())
        assertTrue(server.calls.none { it.second.endsWith("/started") })
        assertFalse(JSONObject(server.calls.last().third!!).getBoolean("ok"))
    }

    @Test
    fun `a removed phone forgets its account`() {
        val host = Host()
        val server = FakeServer(mutableListOf()).apply { status = 401 }
        val agent = RemoteAgent(host, server)
        agent.checkIn(account)
        assertTrue(host.unlinked)
        assertTrue(agent.lastError!!.contains("removed"))
    }

    @Test
    fun `registering and reading the hash list`() {
        val server = FakeServer(mutableListOf())
        val linked = Protocol.register(server, "https://sentinel.test", " ABCD2345 ", "Pixel 9", "1.0.0")
        assertEquals(Account("https://sentinel.test", "d9", "sdv_new", "me@example.com"), linked)
        val sent = JSONObject(server.calls.single().third)
        assertEquals("android", sent.getString("platform"))
        assertEquals("ABCD2345", sent.getString("link_code"))
        assertNull(server.tokens.single())
        assertEquals(setOf("c".repeat(64)), HashList.parse("""{"version":"1","sha256":["${"C".repeat(64)}","short"]}"""))
    }
}

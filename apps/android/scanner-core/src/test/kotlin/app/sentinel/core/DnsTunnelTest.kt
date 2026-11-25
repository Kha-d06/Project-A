package app.sentinel.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsTunnelTest {
    private val app = DnsTunnel.ipv4(DnsTunnel.VIRTUAL_CLIENT)
    private val dns = DnsTunnel.ipv4(DnsTunnel.VIRTUAL_DNS)

    private fun query(name: String, id: Int = 0x1234, type: Int = 1): ByteArray {
        val out = mutableListOf<Byte>(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
        out[0] = (id ushr 8).toByte()
        out[1] = id.toByte()
        for (label in name.split(".")) {
            out += label.length.toByte()
            out += label.toByteArray().toList()
        }
        out += listOf<Byte>(0, (type ushr 8).toByte(), type.toByte(), 0, 1)
        return out.toByteArray()
    }

    private fun packetFor(name: String, port: Int = 40000) = DnsTunnel.buildUdp(app, dns, port, 53, query(name))

    @Test
    fun builtPacketsParseBackWithAValidChecksum() {
        val p = packetFor("example.org")
        assertEquals(0, DnsTunnel.checksum(p, 0, 20), "a correct header sums to zero")
        val udp = DnsTunnel.parseUdp(p)!!
        assertContentEquals(app, udp.source)
        assertEquals(40000, udp.sourcePort)
        assertEquals(53, udp.destinationPort)
        assertEquals("example.org", DnsTunnel.question(udp.payload)!!.name)
    }

    @Test
    fun blockedNamesGetNxdomainBackToTheAskingApp() {
        val filter = DomainFilter(listOf("ads.example", "malware.test"))
        val action = DnsTunnel.decide(packetFor("x.ads.example", 51111), 0, filter).let { it }
        // length 0 is invalid: dropped, never crashed on.
        assertIs<DnsTunnel.Action.Drop>(action)
        val p = packetFor("x.ads.example", 51111)
        val reply = assertIs<DnsTunnel.Action.Reply>(DnsTunnel.decide(p, p.size, filter))
        assertEquals("x.ads.example", reply.blockedName)
        val back = DnsTunnel.parseUdp(reply.packet)!!
        assertContentEquals(dns, back.source)
        assertContentEquals(app, back.destination)
        assertEquals(51111, back.destinationPort)
        val payload = back.payload
        assertEquals(0x1234, ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF), "same id")
        assertEquals(3, payload[3].toInt() and 0x0F, "NXDOMAIN")
        assertTrue(payload[2].toInt() and 0x80 != 0, "it's a response")
        assertEquals(0, DnsTunnel.checksum(reply.packet, 0, 20))
    }

    @Test
    fun otherNamesAreForwardedAndTheAnswerWrappedBack() {
        val p = packetFor("news.example")
        val forward = assertIs<DnsTunnel.Action.Forward>(DnsTunnel.decide(p, p.size, DomainFilter(listOf("ads.example"))))
        assertEquals("news.example", forward.name)
        val answer = forward.query.copyOf().also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte() }
        val wrapped = DnsTunnel.parseUdp(DnsTunnel.wrapAnswer(forward.request, answer))!!
        assertContentEquals(app, wrapped.destination)
        assertContentEquals(answer, wrapped.payload)
    }

    @Test
    fun anythingThatIsntAQueryToTheVirtualServerIsDropped() {
        val filter = DomainFilter(listOf("ads.example"))
        val elsewhere = DnsTunnel.buildUdp(app, DnsTunnel.ipv4("8.8.8.8"), 40000, 53, query("ads.example"))
        assertIs<DnsTunnel.Action.Drop>(DnsTunnel.decide(elsewhere, elsewhere.size, filter))
        val wrongPort = DnsTunnel.buildUdp(app, dns, 40000, 5353, query("ads.example"))
        assertIs<DnsTunnel.Action.Drop>(DnsTunnel.decide(wrongPort, wrongPort.size, filter))
        val tcp = packetFor("ads.example").also { it[9] = 6 }
        assertIs<DnsTunnel.Action.Drop>(DnsTunnel.decide(tcp, tcp.size, filter))
        val fragment = packetFor("ads.example").also { it[6] = 0x20 }
        assertIs<DnsTunnel.Action.Drop>(DnsTunnel.decide(fragment, fragment.size, filter))
        val v6 = packetFor("ads.example").also { it[0] = 0x60 }
        assertIs<DnsTunnel.Action.Drop>(DnsTunnel.decide(v6, v6.size, filter))
        // Truncated and random packets of every small length never throw.
        val p = packetFor("ads.example")
        for (n in 0..p.size) DnsTunnel.decide(p, n, filter)
        for (n in 0..80) DnsTunnel.decide(ByteArray(n) { (it * 37).toByte() }, n, filter)
    }

    @Test
    fun readsQuestionsSafely() {
        assertNull(DnsTunnel.question(ByteArray(5)))
        val response = query("a.example").also { it[2] = 0x81.toByte() }
        assertNull(DnsTunnel.question(response), "responses aren't queries")
        val pointer = query("a.example").copyOfRange(0, 12) + byteArrayOf(0xC0.toByte(), 12, 0, 1, 0, 1)
        assertNull(DnsTunnel.question(pointer), "compressed names in a query are refused")
        assertEquals(28, DnsTunnel.question(query("v6.example", type = 28))!!.type)
    }

    @Test
    fun theFilterMatchesParentsAndTheAllowListWins() {
        val f = DomainFilter(listOf("tracker.example", "BAD.test."), allowed = listOf("ok.tracker.example"))
        assertTrue(f.blocks("tracker.example"))
        assertTrue(f.blocks("cdn.tracker.example."))
        assertTrue(f.blocks("bad.test"))
        assertFalse(f.blocks("ok.tracker.example"))
        assertFalse(f.blocks("a.ok.tracker.example"))
        assertFalse(f.blocks("example.org"))
        assertFalse(f.blocks("not a name"))
        assertEquals(2, f.size)
        val everything = DomainFilter(listOf("google.com", "gstatic.com"))
        assertFalse(everything.blocks("connectivitycheck.gstatic.com"), "captive-portal checks always work")
    }
}

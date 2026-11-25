package app.sentinel.core

/**
 * The packet logic of Qalaa's DNS-only VPN on Android, with no Android
 * dependencies so it is unit-tested on the JVM.
 *
 * The VPN routes only one virtual DNS server address into the app (the usual
 * DNS-only VpnService pattern; Qalaa's own code, no third-party VPN code). So
 * every packet that arrives is an IPv4/UDP query to that address. Each is either
 * answered at once with NXDOMAIN (a blocked name), or its DNS payload is
 * forwarded to the network's real resolver and the reply wrapped back into a
 * packet. All other traffic never enters the VPN.
 */
object DnsTunnel {
    const val VIRTUAL_DNS = "10.111.222.2"
    const val VIRTUAL_CLIENT = "10.111.222.1"

    data class UdpPacket(
        val source: ByteArray,
        val destination: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        val payload: ByteArray,
    )

    data class Question(val id: Int, val name: String, val type: Int, val end: Int)

    sealed class Action {
        /** Write these bytes back into the tunnel. */
        class Reply(val packet: ByteArray, val blockedName: String) : Action()

        /** Send `query` to the real resolver; wrap its answer with [wrapAnswer]. */
        class Forward(val query: ByteArray, val request: UdpPacket, val name: String) : Action()

        object Drop : Action()
    }

    fun ipv4(text: String): ByteArray =
        text.split(".").map { it.toInt().toByte() }.toByteArray().also { require(it.size == 4) }

    /** An IPv4/UDP packet, or null for anything else (IPv6, TCP, fragments, bad lengths). */
    fun parseUdp(packet: ByteArray, length: Int = packet.size): UdpPacket? {
        if (length < 28 || length > packet.size) return null
        val version = (packet[0].toInt() ushr 4) and 0xF
        val ihl = (packet[0].toInt() and 0xF) * 4
        if (version != 4 || ihl < 20 || length < ihl + 8) return null
        val total = u16(packet, 2)
        if (total > length || total < ihl + 8) return null
        val flagsFrag = u16(packet, 6)
        if (flagsFrag and 0x3FFF != 0) return null // a fragment: not a DNS query we can read
        if (packet[9].toInt() != 17) return null // UDP only
        val udpLength = u16(packet, ihl + 4)
        if (udpLength < 8 || ihl + udpLength > total) return null
        return UdpPacket(
            source = packet.copyOfRange(12, 16),
            destination = packet.copyOfRange(16, 20),
            sourcePort = u16(packet, ihl),
            destinationPort = u16(packet, ihl + 2),
            payload = packet.copyOfRange(ihl + 8, ihl + udpLength),
        )
    }

    /** IPv4 + UDP around `payload`, with a correct IP header checksum (UDP checksum 0 is allowed on IPv4). */
    fun buildUdp(source: ByteArray, destination: ByteArray, sourcePort: Int, destinationPort: Int, payload: ByteArray): ByteArray {
        val total = 20 + 8 + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        put16(p, 2, total)
        p[6] = 0x40 // don't fragment
        p[8] = 64 // TTL
        p[9] = 17
        source.copyInto(p, 12)
        destination.copyInto(p, 16)
        put16(p, 10, checksum(p, 0, 20))
        put16(p, 20, sourcePort)
        put16(p, 22, destinationPort)
        put16(p, 24, 8 + payload.size)
        payload.copyInto(p, 28)
        return p
    }

    fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        while (i + 1 < offset + length) {
            sum += u16(data, i)
            i += 2
        }
        if (i < offset + length) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** The first question of a standard query; null for responses, compressed or odd names. */
    fun question(dns: ByteArray): Question? {
        if (dns.size < 12) return null
        val flags = u16(dns, 2)
        if (flags and 0x8000 != 0 || (flags ushr 11) and 0xF != 0) return null // a response, or not QUERY
        if (u16(dns, 4) < 1) return null
        val labels = mutableListOf<String>()
        var i = 12
        while (true) {
            if (i >= dns.size) return null
            val n = dns[i].toInt() and 0xFF
            if (n == 0) {
                i += 1
                break
            }
            if (n and 0xC0 != 0 || i + 1 + n > dns.size || labels.size >= 127) return null
            labels += String(dns, i + 1, n, Charsets.ISO_8859_1).lowercase()
            i += 1 + n
        }
        if (i + 4 > dns.size) return null
        return Question(u16(dns, 0), labels.joinToString("."), u16(dns, i), i + 4)
    }

    /** NXDOMAIN for the query's question: the app gets a clear "doesn't exist" at once. */
    fun nxdomain(dns: ByteArray, q: Question): ByteArray {
        val out = dns.copyOfRange(0, q.end)
        val rd = out[2].toInt() and 0x01
        out[2] = (0x80 or rd).toByte() // QR, opcode 0, RD copied
        out[3] = 0x83.toByte() // RA, RCODE 3
        put16(out, 4, 1)
        put16(out, 6, 0)
        put16(out, 8, 0)
        put16(out, 10, 0)
        return out
    }

    fun decide(packet: ByteArray, length: Int, filter: DomainFilter, virtualDns: ByteArray = ipv4(VIRTUAL_DNS)): Action {
        val udp = parseUdp(packet, length) ?: return Action.Drop
        if (!udp.destination.contentEquals(virtualDns) || udp.destinationPort != 53) return Action.Drop
        val q = question(udp.payload) ?: return Action.Drop
        if (filter.blocks(q.name)) {
            val answer = nxdomain(udp.payload, q)
            return Action.Reply(buildUdp(udp.destination, udp.source, 53, udp.sourcePort, answer), q.name)
        }
        return Action.Forward(udp.payload, udp, q.name)
    }

    /** The resolver's answer as a packet back to the app that asked. */
    fun wrapAnswer(request: UdpPacket, answer: ByteArray): ByteArray =
        buildUdp(request.destination, request.source, 53, request.sourcePort, answer)

    private fun u16(b: ByteArray, at: Int) = ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, at: Int, v: Int) {
        b[at] = (v ushr 8).toByte()
        b[at + 1] = v.toByte()
    }
}

/**
 * Blocked and allowed names. A name is blocked when it or a parent domain is on
 * the block list, unless it or a parent is on the person's allow list.
 * Connectivity checks are never blocked, so captive portals keep working.
 */
class DomainFilter(blocked: Collection<String>, allowed: Collection<String> = emptyList()) {
    private val blocked = blocked.mapNotNull(::clean).toHashSet()
    private val allowed = (allowed.mapNotNull(::clean) + CONNECTIVITY_CHECKS).toHashSet()

    val size: Int get() = blocked.size

    fun blocks(name: String): Boolean {
        val n = clean(name) ?: return false
        return listed(n, blocked) && !listed(n, allowed)
    }

    private fun listed(name: String, set: Set<String>): Boolean {
        var candidate = name
        while (true) {
            if (candidate in set) return true
            val dot = candidate.indexOf('.')
            if (dot < 0) return false
            candidate = candidate.substring(dot + 1)
        }
    }

    companion object {
        val CONNECTIVITY_CHECKS = listOf("connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", "www.google.com")

        fun clean(name: String): String? {
            val n = name.trim().trimEnd('.').lowercase()
            return n.takeIf { it.length in 1..253 && it.all { c -> c.isLetterOrDigit() || c == '.' || c == '-' || c == '_' } && it.contains('.') }
        }
    }
}

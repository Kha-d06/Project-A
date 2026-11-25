package app.sentinel.protect

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import app.sentinel.core.DnsTunnel
import app.sentinel.core.DomainFilter
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Safe DNS on Android: a VpnService whose only route is a virtual DNS server.
 * Android sends every app's DNS lookups to it; blocked names get NXDOMAIN at
 * once, others are asked of the network's own resolver through a socket
 * protected from the VPN. No other traffic enters the tunnel, nothing is
 * logged, and nothing leaves the phone except the lookups the phone would
 * make anyway. The packet logic is in scanner-core (DnsTunnel, tested on the JVM).
 */
class DnsVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "app.sentinel.protect.STOP_DNS"
        @Volatile var running = false
            private set
        val blockedCount = AtomicInteger(0)
        private const val FALLBACK_DNS = "9.9.9.9" // Quad9, which also blocks malware domains
    }

    private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var stop = false
    private val forwarders = Executors.newFixedThreadPool(4)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        if (running) return START_STICKY
        val upstream = upstreamDns()
        val filter = DomainFilter(Engine.get(this).blockedDomains(), Engine.get(this).allowedDomains())
        val established = Builder()
            .setSession("Qalaa Safe DNS")
            .addAddress(DnsTunnel.VIRTUAL_CLIENT, 32)
            .addDnsServer(DnsTunnel.VIRTUAL_DNS)
            .addRoute(DnsTunnel.VIRTUAL_DNS, 32) // only the virtual DNS server is routed in
            .setBlocking(true)
            .also { runCatching { it.addDisallowedApplication(packageName) } }
            .establish() ?: return START_NOT_STICKY // permission revoked or another VPN took over
        tunnel = established
        stop = false
        running = true
        Thread({ loop(established, filter, upstream) }, "qalaa-dns").start()
        return START_STICKY
    }

    /** The network's own resolver, so local names and captive portals keep working; Quad9 if none. */
    private fun upstreamDns(): InetAddress {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val servers = runCatching { cm.getLinkProperties(cm.activeNetwork)?.dnsServers }.getOrNull().orEmpty()
        return servers.firstOrNull { it is Inet4Address && it.hostAddress != DnsTunnel.VIRTUAL_DNS } ?: InetAddress.getByName(FALLBACK_DNS)
    }

    private fun loop(fd: ParcelFileDescriptor, filter: DomainFilter, upstream: InetAddress) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (!stop) {
                val n = input.read(buffer)
                if (n <= 0) continue
                when (val action = DnsTunnel.decide(buffer, n, filter)) {
                    is DnsTunnel.Action.Reply -> {
                        blockedCount.incrementAndGet()
                        synchronized(output) { output.write(action.packet) }
                    }
                    is DnsTunnel.Action.Forward -> forwarders.execute { forward(action, upstream, output) }
                    DnsTunnel.Action.Drop -> Unit
                }
            }
        } catch (_: Exception) {
            // the tunnel was closed
        } finally {
            shutdown()
        }
    }

    private fun forward(action: DnsTunnel.Action.Forward, upstream: InetAddress, output: FileOutputStream) {
        try {
            DatagramSocket().use { socket ->
                protect(socket) // this socket bypasses the VPN, so the lookup reaches the network
                socket.soTimeout = 5_000
                socket.send(DatagramPacket(action.query, action.query.size, upstream, 53))
                val reply = ByteArray(4096)
                val packet = DatagramPacket(reply, reply.size)
                socket.receive(packet)
                val answer = reply.copyOf(packet.length)
                synchronized(output) { output.write(DnsTunnel.wrapAnswer(action.request, answer)) }
            }
        } catch (_: Exception) {
            // no answer: the app's own resolver retries, as it would on any network
        }
    }

    private fun shutdown() {
        stop = true
        running = false
        runCatching { tunnel?.close() }
        tunnel = null
    }

    override fun onRevoke() {
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        forwarders.shutdownNow()
        super.onDestroy()
    }
}

package app.sentinel.core

/**
 * On-phone checks for scam calls and dangerous links in messages.
 *
 * Both work from lists the phone downloads from the owner's SENTINEL server
 * (community-verified scam numbers; malicious domains and exact URLs), so no
 * call, message or link is ever sent to the server.
 */
object ScamChecks {
    /** Same rule as the server: digits only; "+" or "00" prefixes become "+<digits>". */
    fun normalizePhone(raw: String): String {
        val digits = raw.filter { it.isDigit() }
        val trimmed = raw.trim()
        return when {
            trimmed.startsWith("+") -> "+$digits"
            digits.startsWith("00") -> "+${digits.drop(2)}"
            else -> digits
        }
    }

    /**
     * Whether an incoming number is on the list. Numbers from the network usually
     * arrive in international form, but a local form (0501234567) is matched
     * against listed numbers that end with the same national digits.
     */
    fun isListedNumber(raw: String, listed: Set<String>): Boolean {
        val number = normalizePhone(raw)
        if (number.trimStart('+').length < 7) return false
        if (number in listed) return true
        if (number.startsWith("+")) return false
        val national = number.trimStart('0')
        if (national.length < 7) return false
        return listed.any { it.startsWith("+") && it.endsWith(national) && it.length - national.length in 2..4 }
    }

    private val LINK = Regex("""(?i)\b((?:https?://|www\.)[^\s<>"'()]+|[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,24}/[^\s<>"'()]*)""")

    /** Links in a message, including bare "example.com/path" forms that SMS apps make tappable. */
    fun extractLinks(text: String): List<String> =
        LINK.findAll(text)
            .map { it.value.trimEnd('.', ',', ';', ':', '!', '?') }
            .map { if (it.startsWith("http://", true) || it.startsWith("https://", true)) it else "https://$it" }
            .distinct()
            .take(20)
            .toList()

    fun hostOf(url: String): String? {
        val match = Regex("""(?i)^https?://(?:[^@/?#]*@)?([^/:?#]+)""").find(url) ?: return null
        return match.groupValues[1].lowercase().trimEnd('.').ifEmpty { null }
    }

    /** Server-style normalisation: lower-case scheme and host, default port dropped, "/" for an empty path, no fragment. */
    fun normalizeUrl(url: String): String? {
        val match = Regex("""(?i)^(https?)://(?:[^@/?#]*@)?([^/:?#]+)(?::(\d+))?([^?#]*)(\?[^#]*)?""").find(url) ?: return null
        val scheme = match.groupValues[1].lowercase()
        val host = match.groupValues[2].lowercase().trimEnd('.')
        val port = match.groupValues[3]
        val keepPort = port.isNotEmpty() && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80")
        val path = match.groupValues[4].ifEmpty { "/" }
        return "$scheme://$host${if (keepPort) ":$port" else ""}$path${match.groupValues[5]}"
    }

    data class LinkMatch(val url: String, val host: String, val exactPage: Boolean)

    /** Listed links: the exact page is listed, or its domain (or a parent domain) is. */
    fun dangerousLinks(text: String, hosts: Set<String>, urls: Set<String>): List<LinkMatch> =
        extractLinks(text).mapNotNull { link ->
            val host = hostOf(link) ?: return@mapNotNull null
            val normalized = normalizeUrl(link)
            when {
                normalized != null && normalized in urls -> LinkMatch(link, host, exactPage = true)
                parents(host).any { it in hosts } -> LinkMatch(link, host, exactPage = false)
                else -> null
            }
        }

    private fun parents(host: String): List<String> {
        val parts = host.split('.')
        return (0 until parts.size - 1).map { parts.drop(it).joinToString(".") }
    }
}

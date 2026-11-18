package app.sentinel.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ScamChecksTest {
    private val listed = setOf("+971501234567", "+966551112233")

    @Test
    fun phoneNumbersMatchInInternationalAndLocalForm() {
        assertEquals("+971501234567", ScamChecks.normalizePhone("+971 50 123 4567"))
        assertEquals("+971501234567", ScamChecks.normalizePhone("00971-50-123-4567"))
        assertTrue(ScamChecks.isListedNumber("+971 50 123 4567", listed))
        assertTrue(ScamChecks.isListedNumber("0501234567", listed)) // local UAE form
        assertFalse(ScamChecks.isListedNumber("+971501234568", listed))
        assertFalse(ScamChecks.isListedNumber("4567", listed)) // too short to match anything
        assertFalse(ScamChecks.isListedNumber("", listed))
    }

    @Test
    fun linksAreFoundIncludingBareDomains() {
        val text = "Your parcel is held. Pay the fee at dhl-fees.example/pay?id=7 or https://Secure-Login.Evil.Example/x. Thanks!"
        assertEquals(
            listOf("https://dhl-fees.example/pay?id=7", "https://Secure-Login.Evil.Example/x"),
            ScamChecks.extractLinks(text),
        )
        assertEquals("secure-login.evil.example", ScamChecks.hostOf("https://Secure-Login.Evil.Example/x"))
        assertEquals("https://a.example/", ScamChecks.normalizeUrl("HTTPS://A.Example:443"))
        assertEquals("http://a.example:8080/p?q=1", ScamChecks.normalizeUrl("http://a.example:8080/p?q=1#frag"))
    }

    @Test
    fun dangerousLinksMatchListedDomainsAndExactPagesOnly() {
        val hosts = setOf("evil.example")
        val urls = setOf("https://shared.example.org/phish/login")
        val text = "Login: https://secure-login.evil.example/x and https://shared.example.org/phish/login " +
            "but not https://shared.example.org/blog or https://notevil.example/"
        val found = ScamChecks.dangerousLinks(text, hosts, urls)
        assertEquals(listOf("secure-login.evil.example" to false, "shared.example.org" to true), found.map { it.host to it.exactPage })
    }
}

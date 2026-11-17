package app.sentinel.core

/** How sure we are that something is harmful. Matches the website's and desktop app's wording. */
enum class Verdict(val wire: String) {
    MALICIOUS("malicious"),
    SUSPICIOUS("suspicious"),
    /** Not harmful on its own, but worth a look (for example: installed from outside an app store). */
    REVIEW("review"),
    /** Nothing known was found. Never reported as "safe". */
    NO_KNOWN_THREAT("no_known_threat"),
    ;

    companion object {
        fun worst(verdicts: Iterable<Verdict>): Verdict = verdicts.minByOrNull { it.ordinal } ?: NO_KNOWN_THREAT
    }
}

/**
 * One reason behind a verdict. [code] selects the sentence shown to the person
 * (see [Messages]); [args] fills it in, for example the brand an app imitates.
 */
data class Finding(val code: String, val verdict: Verdict, val args: List<String> = emptyList())

enum class CheckStatus { GOOD, WARN, BAD, UNKNOWN }

data class DeviceCheck(val code: String, val status: CheckStatus, val args: List<String> = emptyList())

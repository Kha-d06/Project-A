package app.sentinel.core

import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit

/** Facts about the phone, collected by the app module. Null means "could not be read". */
data class DeviceFacts(
    val androidRelease: String,
    val sdkInt: Int,
    /** Build.VERSION.SECURITY_PATCH, e.g. "2026-10-05". */
    val securityPatch: String?,
    val screenLockSecure: Boolean?,
    val developerOptions: Boolean?,
    val usbDebugging: Boolean?,
    /** Paths or properties that suggest the phone is rooted. */
    val rootIndicators: List<String>,
    /** Labels of non-system apps currently allowed to install other apps. */
    val appsAllowedToInstall: List<String>,
)

object DeviceChecks {
    /** Google publishes patches monthly; three months behind is a warning, six is serious. */
    const val PATCH_WARN_DAYS = 90L
    const val PATCH_BAD_DAYS = 180L

    fun patchAgeDays(patch: String?, today: LocalDate): Long? =
        try {
            patch?.let { ChronoUnit.DAYS.between(LocalDate.parse(it.trim()), today).coerceAtLeast(0) }
        } catch (_: DateTimeParseException) {
            null
        }

    fun assess(facts: DeviceFacts, today: LocalDate = LocalDate.now()): List<DeviceCheck> {
        val checks = mutableListOf<DeviceCheck>()
        val age = patchAgeDays(facts.securityPatch, today)
        checks += when {
            age == null -> DeviceCheck("patch", CheckStatus.UNKNOWN)
            age >= PATCH_BAD_DAYS -> DeviceCheck("patch", CheckStatus.BAD, listOf(facts.securityPatch!!, (age / 30).toString()))
            age >= PATCH_WARN_DAYS -> DeviceCheck("patch", CheckStatus.WARN, listOf(facts.securityPatch!!, (age / 30).toString()))
            else -> DeviceCheck("patch", CheckStatus.GOOD, listOf(facts.securityPatch!!))
        }
        checks += when (facts.screenLockSecure) {
            true -> DeviceCheck("screen_lock", CheckStatus.GOOD)
            false -> DeviceCheck("screen_lock", CheckStatus.BAD)
            null -> DeviceCheck("screen_lock", CheckStatus.UNKNOWN)
        }
        checks += when {
            facts.usbDebugging == true -> DeviceCheck("usb_debugging", CheckStatus.BAD)
            facts.developerOptions == true -> DeviceCheck("developer_options", CheckStatus.WARN)
            facts.developerOptions == null -> DeviceCheck("developer_options", CheckStatus.UNKNOWN)
            else -> DeviceCheck("developer_options", CheckStatus.GOOD)
        }
        checks += if (facts.rootIndicators.isEmpty()) {
            DeviceCheck("root", CheckStatus.GOOD)
        } else {
            DeviceCheck("root", CheckStatus.WARN, listOf(facts.rootIndicators.take(3).joinToString(", ")))
        }
        checks += if (facts.appsAllowedToInstall.isEmpty()) {
            DeviceCheck("unknown_sources", CheckStatus.GOOD)
        } else {
            DeviceCheck("unknown_sources", CheckStatus.WARN, listOf(facts.appsAllowedToInstall.take(5).joinToString(", ")))
        }
        return checks
    }

    /** Short summary for the website's device page (only these values are sent). */
    fun summary(facts: DeviceFacts, today: LocalDate = LocalDate.now()): Map<String, Any?> = mapOf(
        "os" to "Android ${facts.androidRelease}",
        "patch_age_days" to patchAgeDays(facts.securityPatch, today),
        "screen_lock" to facts.screenLockSecure,
        "developer_options" to facts.developerOptions,
        "unknown_sources" to facts.appsAllowedToInstall.size,
    )
}

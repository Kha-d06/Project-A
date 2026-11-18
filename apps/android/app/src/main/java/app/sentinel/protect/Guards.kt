package app.sentinel.protect

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.telecom.Call
import android.telecom.CallScreeningService
import app.sentinel.core.Account
import app.sentinel.core.Protocol
import app.sentinel.core.ScamChecks
import app.sentinel.core.Strings
import java.io.File
import org.json.JSONObject

/**
 * Lists used by the call and message guards, downloaded from the linked Qalaa
 * server during the regular check-in (at most every 6 hours) and kept in the
 * app's private storage. Matching happens on the phone: no call, message or
 * link is ever sent to the server.
 */
object ScamLists {
    private const val REFRESH_MS = 6L * 60 * 60 * 1000

    @Volatile private var phones: Set<String>? = null
    @Volatile private var hosts: Set<String>? = null
    @Volatile private var urls: Set<String>? = null

    private fun phoneFile(context: Context) = File(context.filesDir, "scam-phones.json")
    private fun linkFile(context: Context) = File(context.filesDir, "scam-links.json")

    private fun strings(json: JSONObject, key: String): Set<String> {
        val array = json.optJSONArray(key) ?: return emptySet()
        return (0 until array.length()).map { array.getString(it) }.toSet()
    }

    fun phones(context: Context): Set<String> = phones ?: runCatching { strings(JSONObject(phoneFile(context).readText()), "numbers") }
        .getOrDefault(emptySet()).also { phones = it }

    fun hosts(context: Context): Set<String> = hosts ?: runCatching { strings(JSONObject(linkFile(context).readText()), "hosts") }
        .getOrDefault(emptySet()).also { hosts = it }

    fun urls(context: Context): Set<String> = urls ?: runCatching {
        strings(JSONObject(linkFile(context).readText()), "urls").mapNotNull { ScamChecks.normalizeUrl(it) }.toSet()
    }.getOrDefault(emptySet()).also { urls = it }

    /** Called from the background check-in. Needs a linked account (its device token). */
    fun refreshIfDue(context: Context, account: Account, force: Boolean = false) {
        val prefs = context.getSharedPreferences("sentinel", Context.MODE_PRIVATE)
        if (!force && System.currentTimeMillis() - prefs.getLong("scam_lists_at", 0) < REFRESH_MS) return
        val phoneResponse = HttpTransport.send("GET", Protocol.api(account.server, "/devices/phone-list"), null, account.token)
        if (phoneResponse.status == 200) {
            phoneFile(context).writeText(phoneResponse.body)
            phones = null
        }
        val linkResponse = HttpTransport.send("GET", Protocol.api(account.server, "/devices/blocklist"), null, account.token)
        if (linkResponse.status == 200) {
            linkFile(context).writeText(linkResponse.body)
            hosts = null
            urls = null
        }
        if (phoneResponse.status == 200 || linkResponse.status == 200) {
            prefs.edit().putLong("scam_lists_at", System.currentTimeMillis()).apply()
        }
    }

    fun clear(context: Context) {
        phoneFile(context).delete()
        linkFile(context).delete()
        phones = null; hosts = null; urls = null
    }
}

private const val GUARD_CHANNEL = "guards"

internal fun warn(context: Context, id: Int, title: String, body: String) {
    if (Build.VERSION.SDK_INT >= 33 &&
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) return
    val manager = context.getSystemService(NotificationManager::class.java) ?: return
    val lang = Engine.get(context).lang
    manager.createNotificationChannel(NotificationChannel(GUARD_CHANNEL, Strings.get(lang, "guard_channel"), NotificationManager.IMPORTANCE_HIGH))
    val open = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
    val notification = Notification.Builder(context, GUARD_CHANNEL)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle(title)
        .setContentText(body)
        .setStyle(Notification.BigTextStyle().bigText(body))
        .setContentIntent(open)
        .setAutoCancel(true)
        .build()
    manager.notify(id, notification)
}

/**
 * Screens incoming calls (Android 10+, after the person makes Qalaa the call
 * screening app). A number on the community scam list triggers a warning; it is
 * rejected only if the person turned on "Block reported scam numbers".
 */
@android.annotation.TargetApi(24)
class CallGuard : CallScreeningService() {
    override fun onScreenCall(details: Call.Details) {
        val allow = CallResponse.Builder().build()
        val incoming = Build.VERSION.SDK_INT < 29 || details.callDirection == Call.Details.DIRECTION_INCOMING
        val number = details.handle?.schemeSpecificPart
        if (!incoming || number.isNullOrBlank() || !ScamChecks.isListedNumber(number, ScamLists.phones(this))) {
            respondToCall(details, allow)
            return
        }
        val block = getSharedPreferences("sentinel", MODE_PRIVATE).getBoolean("block_scam_calls", false)
        val lang = Engine.get(this).lang
        if (block) {
            respondToCall(
                details,
                CallResponse.Builder().setDisallowCall(true).setRejectCall(true).setSkipCallLog(false).setSkipNotification(false).build(),
            )
        } else {
            respondToCall(details, allow)
        }
        warn(
            this,
            number.hashCode(),
            Strings.get(lang, if (block) "call_blocked_title" else "call_warning_title"),
            Strings.format(lang, "call_warning_body", number),
        )
    }
}

/**
 * Optional: checks links in incoming message notifications (SMS, WhatsApp,
 * Telegram...) against Qalaa's lists, on the phone, after the person grants
 * notification access. Only the links are looked at, only locally, and nothing
 * is stored or sent.
 */
class MessageGuard : NotificationListenerService() {
    private val recent = ArrayDeque<String>()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName == packageName) return
        val notification = sbn.notification ?: return
        val isMessage = notification.category == Notification.CATEGORY_MESSAGE || notification.extras.containsKey(Notification.EXTRA_MESSAGES)
        if (!isMessage) return
        val extras = notification.extras
        val parts = mutableListOf<CharSequence?>(extras.getCharSequence(Notification.EXTRA_TEXT), extras.getCharSequence(Notification.EXTRA_BIG_TEXT))
        @Suppress("DEPRECATION")
        extras.getParcelableArray(Notification.EXTRA_MESSAGES)?.forEach { bundle ->
            (bundle as? android.os.Bundle)?.getCharSequence("text")?.let { parts.add(it) }
        }
        val text = parts.filterNotNull().joinToString("\n").take(5000)
        if (!text.contains('.')) return
        val found = ScamChecks.dangerousLinks(text, ScamLists.hosts(this), ScamLists.urls(this))
        val fresh = found.filter { it.host !in recent }
        if (fresh.isEmpty()) return
        fresh.forEach { recent.addLast(it.host); if (recent.size > 50) recent.removeFirst() }
        val lang = Engine.get(this).lang
        val app = runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(sbn.packageName, 0)).toString() }
            .getOrDefault(sbn.packageName)
        warn(
            this,
            sbn.key.hashCode(),
            Strings.get(lang, "link_warning_title"),
            Strings.format(lang, "link_warning_body", app, fresh.joinToString(", ") { it.host }),
        )
    }

    companion object {
        fun enabled(context: Context): Boolean {
            val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners") ?: return false
            val me = ComponentName(context, MessageGuard::class.java).flattenToString()
            return flat.split(':').any { it == me }
        }
    }
}

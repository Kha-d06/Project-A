package app.sentinel.protect

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.text.format.DateUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import app.sentinel.core.CheckStatus
import app.sentinel.core.DeviceChecks
import app.sentinel.core.Messages
import app.sentinel.core.Strings
import app.sentinel.core.Verdict
import java.util.concurrent.Executors

/**
 * The phone scanner's only screen. Built in code with platform widgets, so the
 * app needs no extra libraries. Text follows the system language (English or
 * Arabic, right to left).
 */
class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var engine: Engine
    private lateinit var content: LinearLayout
    private var status: TextView? = null
    private var busy = false

    private companion object {
        const val PICK_FILES = 1
        const val GOOD = 0xFF1D6B52.toInt()
        const val WARN = 0xFFA15C07.toInt()
        const val BAD = 0xFFB42318.toInt()
    }

    private val lang get() = engine.lang
    private fun t(key: String) = Strings.get(lang, key)
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        engine = Engine.get(this)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(32))
        }
        val scroll = ScrollView(this).apply { addView(content) }
        // Android 15 draws behind the system bars; keep content clear of them.
        scroll.setOnApplyWindowInsetsListener { view, insets ->
            @Suppress("DEPRECATION")
            view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            insets
        }
        setContentView(scroll)
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        if (engine.account != null) CheckInJob.schedule(this)
        render()
    }

    override fun onResume() {
        super.onResume()
        if (!busy) render()
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    // --- Building blocks ---------------------------------------------------------------

    private fun text(value: String, size: Float = 15f, bold: Boolean = false, color: Int? = null) = TextView(this).apply {
        this.text = value
        textSize = size
        textAlignment = View.TEXT_ALIGNMENT_VIEW_START
        if (bold) setTypeface(typeface, Typeface.BOLD)
        if (color != null) setTextColor(color)
        setPadding(0, dp(4), 0, dp(4))
    }

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        this.text = label
        isAllCaps = false
        setOnClickListener { onClick() }
    }

    private fun card(vararg views: View) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(14), dp(10), dp(14), dp(10))
        background = GradientDrawable().apply {
            cornerRadius = dp(12).toFloat()
            setStroke(dp(1), Color.argb(60, 128, 128, 128))
        }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { setMargins(0, dp(8), 0, dp(8)) }
        views.forEach { addView(it) }
    }

    private fun row(vararg views: View) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        views.forEach { addView(it) }
    }

    private fun background(work: () -> Unit) {
        if (busy) return
        busy = true
        worker.execute {
            try {
                work()
            } catch (error: Exception) {
                runOnUiThread { Toast.makeText(this, Strings.format(lang, "error", error.message ?: error.toString()), Toast.LENGTH_LONG).show() }
            } finally {
                runOnUiThread {
                    busy = false
                    render()
                }
            }
        }
    }

    private fun progress(message: String) = runOnUiThread { status?.text = Strings.format(lang, "scanning_item", message) }

    // --- Screen -----------------------------------------------------------------------------

    private fun render() {
        content.removeAllViews()
        content.addView(text(t("title"), 26f, bold = true))
        content.addView(text(t("subtitle"), 14f))

        // Scanning
        status = text(if (busy) t("scanning") else "", 14f)
        content.addView(
            card(
                button(t("scan")) { background { engine.scan(full = false, progress = ::progress) } },
                button(t("full_scan")) { background { engine.scan(full = true, progress = ::progress) } },
                button(t("pick")) {
                    startActivityForResult(
                        Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*").putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true),
                        PICK_FILES,
                    )
                },
                status!!,
                text(Strings.format(lang, "signatures", engine.signatureCount), 13f),
            ),
        )
        if (!engine.hasFileAccess()) {
            content.addView(card(text(t("file_access_hint"), 14f), button(t("file_access")) { requestFileAccess() }))
        }

        engine.lastReport?.let { report ->
            val attention = report.appsNeedingAttention.size + report.filesNeedingAttention.size
            content.addView(
                text(
                    if (attention == 0) Strings.format(lang, "result_none", report.apps.size, report.files.size)
                    else Strings.format(lang, "result_some", report.apps.size, report.files.size, attention),
                    15f,
                    bold = true,
                    color = if (attention == 0) GOOD else BAD,
                ),
            )
            if (report.appsNeedingAttention.isNotEmpty()) {
                content.addView(text(t("apps_attention"), 18f, bold = true))
                report.appsNeedingAttention.forEach { result ->
                    content.addView(
                        card(
                            text("${result.app.label}  ·  ${result.app.packageName}", 15f, bold = true, color = if (result.verdict == Verdict.MALICIOUS) BAD else WARN),
                            *result.findings.map { text("• " + Messages.finding(it, lang), 14f) }.toTypedArray(),
                            row(
                                button(t("uninstall")) { startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${result.app.packageName}"))) },
                                button(t("app_info")) { startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${result.app.packageName}"))) },
                            ),
                        ),
                    )
                }
            }
            if (report.filesNeedingAttention.isNotEmpty()) {
                content.addView(text(t("files_attention"), 18f, bold = true))
                report.filesNeedingAttention.forEach { result ->
                    content.addView(
                        card(
                            text(result.assessment.name, 15f, bold = true, color = if (result.assessment.verdict == Verdict.MALICIOUS) BAD else WARN),
                            text(result.path, 12f),
                            *result.assessment.findings.map { text("• " + Messages.finding(it, lang), 14f) }.toTypedArray(),
                            button(t("quarantine")) {
                                background {
                                    val moved = engine.quarantineFile(result.path, result.assessment.sha256)
                                    runOnUiThread { Toast.makeText(this, t(if (moved) "quarantined" else "quarantine_failed"), Toast.LENGTH_SHORT).show() }
                                }
                            },
                        ),
                    )
                }
            }
        }

        // Phone check
        content.addView(text(t("phone_check"), 18f, bold = true))
        val checks = DeviceChecks.assess(Inventory.deviceFacts(this))
        content.addView(
            card(
                *checks.map { check ->
                    val color = when (check.status) { CheckStatus.GOOD -> GOOD; CheckStatus.WARN -> WARN; CheckStatus.BAD -> BAD; CheckStatus.UNKNOWN -> null }
                    text((if (check.status == CheckStatus.GOOD) "✓ " else "! ") + Messages.check(check, lang), 14f, color = color)
                }.toTypedArray(),
            ),
        )

        // Quarantine
        val quarantined = engine.quarantined()
        if (quarantined.isNotEmpty()) {
            content.addView(text(t("quarantine_title"), 18f, bold = true))
            content.addView(text(t("quarantine_hint"), 13f))
            quarantined.forEach { item ->
                content.addView(
                    card(
                        text(item.name, 15f, bold = true),
                        text(item.originalPath, 12f),
                        row(
                            button(t("restore")) { background { engine.restore(item.id) } },
                            button(t("delete")) { background { engine.deleteQuarantined(item.id) } },
                        ),
                    ),
                )
            }
        }

        // Account
        content.addView(text(t("account"), 18f, bold = true))
        val linked = engine.account
        if (linked == null) {
            val code = EditText(this).apply {
                hint = t("code")
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                textDirection = View.TEXT_DIRECTION_LTR
            }
            content.addView(card(text(t("account_hint"), 14f), code, button(t("link")) { background { engine.link(code.text.toString()) } }))
        } else {
            val toggle = Switch(this).apply {
                text = t("allow_remote")
                isChecked = engine.remoteAllowed
                setOnCheckedChangeListener { _, checked ->
                    engine.remoteAllowed = checked
                    background { engine.checkIn() }
                }
            }
            val lastCheckIn = engine.lastCheckIn().let { if (it == 0L) t("never") else DateUtils.getRelativeTimeSpanString(it).toString() }
            content.addView(
                card(
                    text(Strings.format(lang, "linked", linked.email), 15f, bold = true),
                    toggle,
                    text(t("allow_remote_hint"), 13f),
                    text(Strings.format(lang, "last_check_in", lastCheckIn), 13f),
                    *listOfNotNull(engine.lastCheckInError?.let { text(it, 13f, color = BAD) }).toTypedArray(),
                    button(t("unlink")) {
                        AlertDialog.Builder(this).setMessage(t("unlink")).setPositiveButton(t("unlink")) { _, _ ->
                            background {
                                engine.unlink()
                                CheckInJob.cancel(this)
                            }
                        }.setNegativeButton(android.R.string.cancel, null).show()
                    },
                ),
            )
        }

        renderGuards(linked != null)

        content.addView(button(t("website")) { startActivity(Intent(this, com.google.androidbrowserhelper.trusted.LauncherActivity::class.java)) })
        content.addView(text(t("limits"), 12f))
    }

    /** Call screening and message link checks: both opt-in, both matched on the phone. */
    private fun renderGuards(linked: Boolean) {
        content.addView(text(t("guards"), 18f, bold = true))
        if (!linked) {
            content.addView(card(text(t("guards_hint"), 13f), text(t("guards_need_account"), 14f)))
            return
        }
        val prefs = getSharedPreferences("sentinel", MODE_PRIVATE)
        val views = mutableListOf<View>(text(t("guards_hint"), 13f))
        if (Build.VERSION.SDK_INT >= 29) {
            val roles = getSystemService(android.app.role.RoleManager::class.java)
            if (roles != null && roles.isRoleHeld(android.app.role.RoleManager.ROLE_CALL_SCREENING)) {
                views.add(text(t("call_guard_on"), 14f, color = GOOD))
                views.add(Switch(this).apply {
                    text = t("block_calls")
                    isChecked = prefs.getBoolean("block_scam_calls", false)
                    setOnCheckedChangeListener { _, checked -> prefs.edit().putBoolean("block_scam_calls", checked).apply() }
                })
            } else if (roles != null && roles.isRoleAvailable(android.app.role.RoleManager.ROLE_CALL_SCREENING)) {
                views.add(button(t("call_guard")) {
                    @Suppress("DEPRECATION")
                    startActivityForResult(roles.createRequestRoleIntent(android.app.role.RoleManager.ROLE_CALL_SCREENING), 7)
                })
            }
        } else {
            views.add(text(t("call_guard_unsupported"), 13f))
        }
        if (MessageGuard.enabled(this)) {
            views.add(text(t("message_guard_on"), 14f, color = GOOD))
        } else {
            views.add(text(t("message_guard_hint"), 13f))
            views.add(button(t("message_guard")) { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) })
        }
        views.add(text(Strings.format(lang, "lists_status", ScamLists.phones(this).size, ScamLists.hosts(this).size), 12f))
        content.addView(card(*views.toTypedArray()))
        // The first time the guards are shown, fetch the lists instead of waiting for the next check-in.
        if (prefs.getLong("scam_lists_at", 0) == 0L) {
            engine.account?.let { account -> background { ScamLists.refreshIfDue(this, account, force = true) } }
        }
    }

    private fun requestFileAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
            } catch (_: Exception) {
                startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
            }
        } else {
            requestPermissions(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE), 1)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (!busy) render()
    }

    @Deprecated("Platform API; this app uses no AndroidX activity-result library.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != PICK_FILES || resultCode != RESULT_OK || data == null) return
        val uris = buildList {
            data.data?.let { add(it) }
            val clip = data.clipData
            if (clip != null) for (i in 0 until clip.itemCount) add(clip.getItemAt(i).uri)
        }.distinct()
        background {
            val results = engine.scanPicked(uris)
            val flagged = results.filter { it.assessment.verdict == Verdict.MALICIOUS || it.assessment.verdict == Verdict.SUSPICIOUS || it.assessment.verdict == Verdict.REVIEW }
            runOnUiThread {
                val message = if (flagged.isEmpty()) {
                    Strings.format(lang, "result_none", 0, results.size)
                } else {
                    flagged.joinToString("\n\n") { r -> r.assessment.name + "\n" + r.assessment.findings.joinToString("\n") { "• " + Messages.finding(it, lang) } }
                }
                AlertDialog.Builder(this).setMessage(message).setPositiveButton(android.R.string.ok, null).show()
            }
        }
    }
}

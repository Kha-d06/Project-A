package app.sentinel.protect

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import app.sentinel.core.AppInfo
import app.sentinel.core.DeviceFacts
import java.io.File
import java.security.MessageDigest

/** Reads installed apps and device settings. Needs QUERY_ALL_PACKAGES to see every app. */
object Inventory {
    private const val MAX_APK_BYTES = 512L * 1024 * 1024

    @Suppress("DEPRECATION")
    private fun installed(pm: PackageManager, flags: Int): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        else pm.getInstalledPackages(flags)

    @Suppress("DEPRECATION")
    private fun details(pm: PackageManager, name: String, flags: Int): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(name, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else pm.getPackageInfo(name, flags)
    } catch (_: Exception) {
        null
    }

    @Suppress("DEPRECATION")
    private fun installer(pm: PackageManager, name: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(name).installingPackageName else pm.getInstallerPackageName(name)
    } catch (_: Exception) {
        null
    }

    fun sha256(file: File): String? {
        if (!file.canRead() || file.length() > MAX_APK_BYTES) return null
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /** Every installed app. Apps that came with the phone are hashed too, so known malware is caught there. */
    fun apps(context: Context, progress: (Int, Int) -> Unit = { _, _ -> }): List<AppInfo> {
        val pm = context.packageManager
        val packages = installed(pm, PackageManager.GET_PERMISSIONS).filter { it.packageName != context.packageName }
        val defaultSms = try { Telephony.Sms.getDefaultSmsPackage(context) } catch (_: Exception) { null }
        return packages.mapIndexedNotNull { index, info ->
            progress(index + 1, packages.size)
            val application = info.applicationInfo ?: return@mapIndexedNotNull null
            val system = application.flags and ApplicationInfo.FLAG_SYSTEM != 0
            // Services and receivers are read one app at a time: all at once can exceed Binder's size limit.
            val components = if (system) null else details(pm, info.packageName, PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS)
            val bound = buildSet {
                components?.services?.forEach { service -> service.permission?.let { add(it) } }
                components?.receivers?.forEach { receiver -> receiver.permission?.let { add(it) } }
            }
            AppInfo(
                packageName = info.packageName,
                label = application.loadLabel(pm).toString(),
                versionName = info.versionName,
                isSystem = system,
                installer = installer(pm, info.packageName),
                targetSdk = application.targetSdkVersion,
                requestedPermissions = info.requestedPermissions?.toSet() ?: emptySet(),
                boundPermissions = bound,
                hasLauncherIcon = pm.getLaunchIntentForPackage(info.packageName) != null,
                isDefaultSmsApp = info.packageName == defaultSms,
                apkSha256 = runCatching { sha256(File(application.sourceDir)) }.getOrNull(),
            )
        }
    }

    private val ROOT_PATHS = listOf("/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su", "/system/app/Superuser.apk", "/system/bin/magisk")
    private val ROOT_APPS = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu", "io.github.huskydg.magisk")

    @Suppress("DEPRECATION")
    fun deviceFacts(context: Context): DeviceFacts {
        val resolver = context.contentResolver
        val pm = context.packageManager
        fun global(name: String): Boolean? = try { Settings.Global.getInt(resolver, name) != 0 } catch (_: Settings.SettingNotFoundException) { false } catch (_: Exception) { null }
        val root = buildList {
            ROOT_PATHS.filter { File(it).exists() }.forEach { add(it) }
            ROOT_APPS.filter { details(pm, it, 0) != null }.forEach { add(it) }
            if (Build.TAGS?.contains("test-keys") == true) add("test-keys build")
        }
        val installers = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= 29) {
            val ops = context.getSystemService(AppOpsManager::class.java)
            installed(pm, PackageManager.GET_PERMISSIONS)
                .filter { info -> info.applicationInfo?.let { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 } == true }
                .filter { info -> info.requestedPermissions?.contains("android.permission.REQUEST_INSTALL_PACKAGES") == true }
                .forEach { info ->
                    val uid = info.applicationInfo!!.uid
                    val mode = try { ops!!.unsafeCheckOpNoThrow("android:request_install_packages", uid, info.packageName) } catch (_: Exception) { AppOpsManager.MODE_DEFAULT }
                    if (mode == AppOpsManager.MODE_ALLOWED) installers += info.applicationInfo!!.loadLabel(pm).toString()
                }
        }
        return DeviceFacts(
            androidRelease = Build.VERSION.RELEASE ?: "?",
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH,
            screenLockSecure = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure,
            developerOptions = global(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
            usbDebugging = global(Settings.Global.ADB_ENABLED),
            rootIndicators = root,
            appsAllowedToInstall = installers,
        )
    }
}

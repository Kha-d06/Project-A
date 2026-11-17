plugins {
    id("com.android.application")
}

val siteHost: String = (project.findProperty("siteHost") as String?) ?: "sentinel.example.org"
val siteUrl = "https://$siteHost"

android {
    namespace = "app.sentinel.protect"
    compileSdk = 35

    defaultConfig {
        // Change this before publishing: it must be unique on Google Play and match
        // SENTINEL_ANDROID_PACKAGE on the server (for /.well-known/assetlinks.json).
        applicationId = "app.sentinel.protect"
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        manifestPlaceholders["hostName"] = siteHost
        manifestPlaceholders["defaultUrl"] = "$siteUrl/scan?utm_source=android"
        manifestPlaceholders["launcherName"] = "SENTINEL"
        resValue(
            "string",
            "asset_statements",
            """[{ "relation": ["delegate_permission/common.handle_all_urls"], "target": { "namespace": "web", "site": "$siteUrl" } }]""",
        )
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("com.google.androidbrowserhelper:androidbrowserhelper:2.5.0")
}

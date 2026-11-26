plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val siteHost: String = (project.findProperty("siteHost") as String?) ?: "qalaa.example.org"
val siteUrl = "https://$siteHost"

android {
    namespace = "app.sentinel.protect"
    compileSdk = 35

    defaultConfig {
        // Change this before publishing: it must be unique on Google Play and match
        // SENTINEL_ANDROID_PACKAGE on the server (for /.well-known/assetlinks.json).
        applicationId = "app.qalaa.protect"
        minSdk = 29
        targetSdk = 35
        versionCode = 2
        versionName = "0.2.0"
        buildConfigField("String", "SITE_URL", "\"$siteUrl\"")

        manifestPlaceholders["hostName"] = siteHost
        manifestPlaceholders["defaultUrl"] = "$siteUrl/scan?utm_source=android"
        manifestPlaceholders["launcherName"] = "Qalaa"
        resValue(
            "string",
            "asset_statements",
            """[{ "relation": ["delegate_permission/common.handle_all_urls"], "target": { "namespace": "web", "site": "$siteUrl" } }]""",
        )
    }

    // Release signing is optional: pass -PsigningStore=<keystore> and set
    // ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS and ANDROID_KEY_PASSWORD
    // (the release workflow does this from repository secrets).
    val signingStore = project.findProperty("signingStore") as String?
    if (signingStore != null) {
        signingConfigs {
            create("release") {
                storeFile = file(signingStore)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (signingStore != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("com.google.androidbrowserhelper:androidbrowserhelper:2.5.0")
    implementation(project(":scanner-core"))
}

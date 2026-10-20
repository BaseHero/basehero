pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
    plugins {
        id("com.android.library") version "8.11.0"
        id("org.jetbrains.kotlin.android") version "1.9.25"
    }
}
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }
rootProject.name = "bh-qr-scan-android"
// The plugin base classes come from the Tauri crate cargo resolved for this
// workspace; the app build includes the same project from its generated settings.
val tauriAndroid = providers.gradleProperty("tauriAndroidDir").orNull
    ?: error("pass -PtauriAndroidDir=<tauri crate>/mobile/android (scripts/check.sh android-qr-scan does)")
include(":tauri-android")
project(":tauri-android").projectDir = file(tauriAndroid)

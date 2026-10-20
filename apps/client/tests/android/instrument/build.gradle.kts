buildscript {
    repositories { google(); mavenCentral() }
    dependencies { classpath("com.android.tools.build:gradle:8.11.0") }
}
apply(plugin = "com.android.application")
repositories { google(); mavenCentral() }

configure<com.android.build.gradle.AppExtension> {
    compileSdkVersion(36)
    namespace = "app.basehero.continuityinstrument"
    defaultConfig {
        applicationId = "app.basehero.continuityinstrument"
        minSdk = 24
        targetSdk = 36
    }
}

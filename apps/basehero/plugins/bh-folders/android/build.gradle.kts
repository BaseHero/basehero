plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.basehero.folders"
    compileSdk = 36
    defaultConfig { minSdk = 24 }
    kotlinOptions { jvmTarget = "1.8" }
}

dependencies {
    implementation(project(":tauri-android"))
    implementation("androidx.activity:activity:1.10.1")
}

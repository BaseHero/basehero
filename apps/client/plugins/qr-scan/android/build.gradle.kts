plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.basehero.qrscan"
    compileSdk = 36
    defaultConfig {
        minSdk = 24
    }
    kotlinOptions { jvmTarget = "1.8" }
}

dependencies {
    val camerax = "1.5.1"
    implementation("androidx.camera:camera-core:$camerax")
    implementation("androidx.camera:camera-camera2:$camerax")
    implementation("androidx.camera:camera-lifecycle:$camerax")
    implementation("androidx.camera:camera-view:$camerax")
    // Algorithmic QR decoding (Apache-2.0); no model, no network.
    implementation("com.google.zxing:core:3.5.4")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation(project(":tauri-android"))
    testImplementation("junit:junit:4.13.2")
}

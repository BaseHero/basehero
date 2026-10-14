plugins {
    id("com.android.library") version "8.11.0"
    id("org.jetbrains.kotlin.android") version "1.9.25"
}

android {
    namespace = "app.basehero.devicekeys"
    compileSdk = 36
    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }
    kotlinOptions { jvmTarget = "1.8" }
}

dependencies {
    implementation("androidx.biometric:biometric:1.1.0")
    // TauriActivity is an AppCompatActivity (a FragmentActivity).
    implementation("androidx.appcompat:appcompat:1.7.1")
    testImplementation("junit:junit:4.13.2")
}

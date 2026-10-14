buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.11.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.25")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

// Only feature builds include this module. Keep the app's release dependency
// versions when the published plugin requests newer appcompat/material versions
// that require a newer Android toolchain. Never downgrade release's other libs.
if (findProject(":tauri-plugin-webdriver") != null) {
    allprojects {
        configurations.all {
            resolutionStrategy.eachDependency {
                if (requested.group == "androidx.appcompat") useVersion("1.7.1")
                if (requested.group == "com.google.android.material") useVersion("1.12.0")
            }
        }
    }
}

tasks.register("clean").configure {
    delete("build")
}

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
        // rustls-platform-verifier's Kotlin half, published by the rustls project.
        exclusiveContent {
            forRepository {
                maven {
                    url = uri("https://github.com/rustls/rustls-platform-verifier/raw/maven-archive/android-release-support/maven/")
                }
            }
            filter { includeGroup("org.rustls") }
        }
    }
}

tasks.register("clean").configure {
    delete("build")
}

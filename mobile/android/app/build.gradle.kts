plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.openstream"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.openstream"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-Wall", "-Wextra", "-Werror")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Release signing reads an untracked properties file so no
            // keystore material ever lands in version control. Copy
            // signing.properties.example to signing.properties and fill it
            // in; without it the release APK stays unsigned by this build.
            val signingProps = java.util.Properties()
            val signingFile = rootProject.file("signing.properties")
            if (signingFile.exists()) {
                signingFile.inputStream().use(signingProps::load)
                signingConfigs {
                    create("release") {
                        storeFile = file(signingProps.getProperty("storeFile"))
                        storePassword = signingProps.getProperty("storePassword")
                        keyAlias = signingProps.getProperty("keyAlias")
                        keyPassword = signingProps.getProperty("keyPassword")
                    }
                }
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    alias(libs.plugins.android.application)
    // AGP 9.0 起内置 Kotlin 支持（android.builtInKotlin 默认 true）：
    // org.jetbrains.kotlin.android 插件与新 DSL 不兼容，再应用会直接报
    // "The 'org.jetbrains.kotlin.android' plugin is no longer required for Kotlin support since AGP 9.0"。
    // 因此这里不应用任何 KGP 插件，Kotlin 源码由 AGP 内置的 KGP 编译。
}

android {
    namespace = "cn.nizou.hyperosprobe"
    compileSdk = 36

    defaultConfig {
        applicationId = "cn.nizou.hyperosprobe"
        minSdk = 33
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        resources {
            excludes += setOf("/META-INF/*.version", "/META-INF/LICENSE*", "/META-INF/NOTICE*")
        }
    }

    lint {
        abortOnError = false
    }
}

// 内置 Kotlin 下没有 kotlin {} 扩展，jvmTarget 必须与 compileOptions 的 Java 21 对齐，
// 否则报 "Inconsistent JVM-target compatibility"。
tasks.withType<KotlinCompile> {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
    }
}

dependencies {
    // libxposed 只用于编译，运行时由 LSPosed 框架提供
    compileOnly(libs.libxposed.api)
}

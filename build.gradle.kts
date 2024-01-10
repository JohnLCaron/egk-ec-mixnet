plugins {
    kotlin("jvm") version "1.9.21"
    alias(libs.plugins.serialization)
}

group = "org.cryptobiotic"
version = "0.5"

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("libs/egklib-jvm-2.0.3-SNAPSHOT.jar"))
    implementation(libs.bundles.eglib)
    implementation(libs.bundles.logging)
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(19)
}
plugins {
    kotlin("jvm") version "1.9.22"
    application
    alias(libs.plugins.serialization)
}

group = "org.cryptobiotic"
version = "0.7-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("libs/egklib-jvm-2.0.3-SNAPSHOT.jar"))
    implementation(files("libs/verificatum-vcr-3.1.0.jar"))
    implementation(files("libs/verificatum-vmn-3.1.0.jar"))

    implementation(libs.bundles.eglib)
    implementation(libs.bundles.xmlutil)
    implementation(libs.bundles.logging)
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}
tasks.register("fatJar", Jar::class.java) {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    archiveBaseName = "egkmixnet"

    manifest {
        attributes("Main-Class" to "org.cryptobiotic.verificabitur.vmn.RunVmnVerifier")
    }
    from(configurations.runtimeClasspath.get()
        .onEach { println("add from runtimeClasspath: ${it.name}") }
        .map { if (it.isDirectory) it else zipTree(it) })
    val sourcesMain = sourceSets.main.get()
    sourcesMain.allSource.forEach { println("add from sources: ${it.name}") }
    from(sourcesMain.output)
}
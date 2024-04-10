import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.9.22"
    application
    alias(libs.plugins.serialization)
}

group = "org.cryptobiotic"
version = "2.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("libs/egk-ec-2.1-SNAPSHOT.jar"))
    implementation(files("libs/verificatum-vecj-2.2.0.jar"))
    implementation(libs.bundles.eglib)
    implementation(libs.bundles.xmlutil)
    implementation(libs.bundles.logging)
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

///// LOOK
tasks {
    val ENABLE_PREVIEW = "--enable-preview"
    withType<JavaCompile>() {
        options.compilerArgs.add(ENABLE_PREVIEW)
        // Optionally we can show which preview feature we use.
        options.compilerArgs.add("-Xlint:preview")
        // options.compilerArgs.add("--enable-native-access=org.openjdk.jextract")
        // Explicitly setting compiler option --release
        // is needed when we wouldn't set the
        // sourceCompatiblity and targetCompatibility
        // properties of the Java plugin extension.
        options.release.set(17)
    }
    withType<Test>().all {
        useJUnitPlatform()
        minHeapSize = "512m"
        maxHeapSize = "8g"
        jvmArgs = listOf("-Xss128m", "--enable-preview")

        // Make tests run in parallel
        // More info: https://www.jvt.me/posts/2021/03/11/gradle-speed-parallel/
        systemProperties["junit.jupiter.execution.parallel.enabled"] = "true"
        systemProperties["junit.jupiter.execution.parallel.mode.default"] = "concurrent"
        systemProperties["junit.jupiter.execution.parallel.mode.classes.default"] = "concurrent"
    }
    withType<JavaExec>().all {
        jvmArgs("--enable-preview")
    }
    withType<KotlinCompile> {
        kotlinOptions.jvmTarget = "17"
    }
}
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

kotlin {
    jvmToolchain(17)
}
tasks.test {
    useJUnitPlatform()
}

tasks.register<Jar>("uberJar") {
    archiveClassifier = "uber"
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    manifest {
        attributes("Main-Class" to "org.cryptobiotic.mixnet.RunVerifier")
    }

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
}

/*
tasks.register("fatJar", Jar::class.java) {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    archiveBaseName = "egkmixnet"

    manifest {
        attributes("Main-Class" to "org.cryptobiotic.mixnet.RunVerifier")
    }
    from(configurations.runtimeClasspath.get()
        .onEach { println("add from runtimeClasspath: ${it.name}") }
        .map { if (it.isDirectory) it else zipTree(it) })
    val sourcesMain = sourceSets.main.get()
    sourcesMain.allSource.forEach { println("add from sources: ${it.name}") }
    from(sourcesMain.output)
}
 */
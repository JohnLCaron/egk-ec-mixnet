import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.9.22"
    application
    alias(libs.plugins.serialization)
}

group = "org.cryptobiotic"
version = "0.84-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("libs/egklib-jvm-2.0.4-SNAPSHOT.jar"))
    implementation("net.java.dev.jna:jna:5.14.0")

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
        options.release.set(21)
    }
    withType<Test>().all {
        useJUnitPlatform()
        jvmArgs("--enable-preview")
        minHeapSize = "512m"
        maxHeapSize = "4g"
    }
    withType<JavaExec>().all {
        jvmArgs("--enable-preview")
    }
    withType<KotlinCompile> {
        kotlinOptions.jvmTarget = "21"
    }
}
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

kotlin {
    jvmToolchain(21)
}
tasks.test {
    useJUnitPlatform()
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
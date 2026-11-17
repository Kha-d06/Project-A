// Scanning logic with no Android dependencies, so it is unit-tested on the JVM:
//   gradle :scanner-core:test
plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Android ships org.json; the JVM tests use the same API from Maven Central.
    compileOnly("org.json:json:20251224")
    testImplementation("org.json:json:20251224")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

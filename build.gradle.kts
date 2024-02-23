plugins {
    id("org.jetbrains.kotlin.jvm") version "1.9.0"
    id("fabric-loom") version "1.5.7"
    id("maven-publish")
    java
}

val archives_base_name: String by project
base.archivesName.set(archives_base_name)

val javaVersion = 17

dependencies {
    minecraft("com.mojang:minecraft:${property("minecraft_version")}")
    mappings("net.fabricmc:yarn:${property("yarn_mappings")}:v2")
    modImplementation("net.fabricmc:fabric-loader:${property("loader_version")}")

    modImplementation("net.fabricmc:fabric-language-kotlin:${property("fabric_kotlin_version")}")
    modImplementation("net.fabricmc.fabric-api:fabric-api:${property("fabric_version")}")

    modImplementation(files("./ghidra.jar"))
}

tasks {
    compileKotlin {
        kotlinOptions {
            jvmTarget = javaVersion.toString()
        }
    }

    compileJava {
        this.options.encoding = "UTF-8"
        this.options.release = javaVersion
    }

    processResources {
        filteringCharset = "UTF-8"
        inputs.property("version", project.version)
        filesMatching("fabric.mod.json") {
            expand(mapOf("version" to project.version))
        }
    }
}

java {
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}

loom {
    accessWidenerPath = file("src/main/resources/enderdragon.accesswidener")
}

package com.notnite.enderdragon

import generic.jar.ResourceFile
import ghidra.GhidraJarApplicationLayout
import net.fabricmc.loader.api.FabricLoader
import kotlin.io.path.absolute

// Fixes for jar shadowing
class DummyApplicationLayout : GhidraJarApplicationLayout() {
    override fun findGhidraApplicationRootDirs(): MutableCollection<ResourceFile> {
        if (FabricLoader.getInstance().isDevelopmentEnvironment)
            return super.findGhidraApplicationRootDirs()

        val thisJar = FabricLoader.getInstance().getModContainer("enderdragon").get().rootPaths.first()
            .absolute()
            .toUri()
        val appPropUrl = thisJar.toURL().toExternalForm() + "_Root/Ghidra/application.properties"
        val rootDir = ResourceFile(appPropUrl).parentFile
        return mutableListOf(rootDir)
    }

    override fun findExtensionInstallationDirectories(): MutableList<ResourceFile> {
        if (FabricLoader.getInstance().isDevelopmentEnvironment)
            return super.findExtensionInstallationDirectories()

        val thisJar = FabricLoader.getInstance().getModContainer("enderdragon").get().rootPaths.first()
            .absolute()
            .toUri()
        val extensionInstallUrl = thisJar.toURL().toExternalForm() + "_Root/Ghidra/Extensions"
        val extensionInstallDir = ResourceFile(extensionInstallUrl)
        return mutableListOf(extensionInstallDir)
    }
}
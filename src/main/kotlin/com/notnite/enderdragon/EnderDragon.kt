package com.notnite.enderdragon

import com.mojang.brigadier.arguments.StringArgumentType
import ghidra.GhidraJarApplicationLayout
import ghidra.app.decompiler.DecompInterface
import ghidra.base.project.GhidraProject
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.model.ProjectLocator
import ghidra.framework.project.DefaultProject
import ghidra.framework.project.DefaultProjectManager
import ghidra.program.model.listing.Program
import net.fabricmc.api.ClientModInitializer
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback
import net.minecraft.server.command.CommandManager
import net.minecraft.text.Text
import java.io.File

object EnderDragon : ClientModInitializer {
    private var project: GhidraProject? = null
    private var program: Program? = null

    fun decomp(addr: String): String {
        if (program == null || program!!.isClosed) return ""
        val decompInterface = DecompInterface()
        decompInterface.openProgram(program)
        val functionManager = program!!.functionManager

        val offset = addr.toLong(16)
        val function = program!!.addressFactory.defaultAddressSpace.getAddress(offset)
        val functionAt = functionManager.getFunctionContaining(function)

        val results = decompInterface.decompileFunction(functionAt, 0, null)
        val c = results.decompiledFunction.c

        decompInterface.dispose()

        return c.replace("\r", "")
    }

    override fun onInitializeClient() {
        val config = HeadlessGhidraApplicationConfiguration()
        config.isInitializeLogging = false // Still messes with log4j so /shrug
        Application.initializeApplication(
            GhidraJarApplicationLayout(), config
        )

        CommandRegistrationCallback.EVENT.register { dispatcher, registryAccess, env ->
            val cmd = CommandManager.literal("enderdragon")

            cmd.then(
                CommandManager.literal("open").then(
                    CommandManager.argument("project", StringArgumentType.string()).then(
                        CommandManager.argument("executable", StringArgumentType.string()).executes { context ->
                            if (this.program != null) {
                                if (!this.program!!.isClosed) this.project!!.close(this.program)
                                this.program = null
                            }

                            if (this.project != null) {
                                this.project!!.close()
                                this.project = null
                            }
                            

                            val projectDir = StringArgumentType.getString(context, "project")
                            val projectDirFiles = File(projectDir).listFiles { _, name -> name.endsWith(".gpr") }
                            val projectName = projectDirFiles?.get(0)?.nameWithoutExtension ?: "Untitled"
                            val executableName = StringArgumentType.getString(context, "executable")
                            this.project = GhidraProject.openProject(projectDir, projectName)
                            this.program = this.project!!.openProgram(
                                "/", // Assume root
                                executableName,
                                false
                            )

                            context.source.sendMessage(
                                Text.of("Opened $executableName in $projectName")
                            )

                            1
                        })
                )
            )

            cmd.then(
                CommandManager.literal("decompile")
                    .then(CommandManager.argument("addr", StringArgumentType.string()).executes { context ->
                        if (this.program == null) {
                            context.source.sendMessage(
                                Text.of("No program is open")
                            )
                            return@executes 0
                        }

                        val name = StringArgumentType.getString(context, "addr")
                        context.source.sendMessage(Text.of(decomp(name)))
                        1
                    })
            )

            dispatcher.register(cmd)
        }
    }
}

class DummyProjectManager : DefaultProjectManager()
class DummyProject(projectManager: DefaultProjectManager?, projectLocator: ProjectLocator?, resetOwner: Boolean) :
    DefaultProject(projectManager, projectLocator, resetOwner)

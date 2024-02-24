package com.notnite.enderdragon

import com.mojang.brigadier.arguments.StringArgumentType
import ghidra.app.decompiler.DecompInterface
import ghidra.base.project.GhidraProject
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.protocol.ghidra.Handler
import ghidra.program.model.listing.Program
import net.fabricmc.api.ClientModInitializer
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback
import net.fabricmc.loader.api.FabricLoader
import net.minecraft.text.Text
import java.io.File
import java.net.URL


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
            //GhidraJarApplicationLayout(),
            DummyApplicationLayout(),
            config
        )

        // Fix Ghidra's URL handler (almost certainly breaking other mods)
        if (!FabricLoader.getInstance().isDevelopmentEnvironment) {
            URL.setURLStreamHandlerFactory { protocol ->
                when (protocol) {
                    "ghidra" -> Handler()
                    else -> null
                }
            }
        }

        ClientCommandRegistrationCallback.EVENT.register { dispatcher, registryAccess ->
            val cmd = ClientCommandManager.literal("enderdragon")

            cmd.then(
                ClientCommandManager.literal("open").then(
                    ClientCommandManager.argument("project", StringArgumentType.string()).then(
                        ClientCommandManager.argument("executable", StringArgumentType.string()).executes { context ->
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

                            context.source.sendFeedback(
                                Text.of("Opened $executableName in $projectName")
                            )

                            1
                        })
                )
            )

            cmd.then(
                ClientCommandManager.literal("decompile")
                    .then(ClientCommandManager.argument("addr", StringArgumentType.string()).executes { context ->
                        if (this.program == null) {
                            context.source.sendError(
                                Text.of("No program is open")
                            )
                            return@executes 0
                        }

                        val name = StringArgumentType.getString(context, "addr")
                        context.source.sendFeedback(Text.of(decomp(name)))
                        1
                    })
            )

            dispatcher.register(cmd)
        }
    }
}

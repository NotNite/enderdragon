# enderdragon

Ghidra in Minecraft.

![](https://namazu.photos/i/aaz7dc0l.png)

## Using

- Don't
- Download Ghidra
- Edit `Ghidra/Features/FileFormats/Module.manifest` and add `EXCLUDE FROM GHIDRA JAR: true`
  - This is to prevent an incompatible version of asm from being loaded, breaking fabric-loader
- Run `buildGhidraJar` in the support folder
- Manually delete the GSON classes from the built jar
  - This is to prevent conflicts which would break core resource loading in Minecraft
- Put it into this directory and `./gradlew build` like usual
- Install the mod (along with Fabric API and Fabric Language Kotlin) into Minecraft and run it
- Open a project like so: `/enderdragon open <project path> <executable name>`
- Use `/enderdragon decompile <addr>` to decompile an address (specify hex without the 0x prefix)

## Known issues

- This existing
- Ghidra breaks the Log4j Minecraft config so all logging information is voided
- Users have to manually fix dependencies instead of them being shadowed at build

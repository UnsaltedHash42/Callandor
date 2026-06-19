import Foundation

class Scanner {

    let path: String

    init(path: String) {
        self.path = path
    }

    func run() -> ScanResult {
        var vulnerabilities: [Vulnerability] = []
        var scannedBinaries: [ScannedBinary] = []
        let fileManager = FileManager.default
        let url = URL(fileURLWithPath: path)

        FileHandle.standardError.write("Starting scan of \(path)...\n".data(using: .utf8)!)

        guard let enumerator = fileManager.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else {
            print("Error: Could not enumerate \(path)")
            return ScanResult(vulnerabilities: [], scannedBinaries: [])
        }

        var count = 0

        while let fileURL = enumerator.nextObject() as? URL {
            // Skip symlinks to avoid loops
            if let vals = try? fileURL.resourceValues(forKeys: [.isSymbolicLinkKey]),
               vals.isSymbolicLink == true {
                continue
            }

            // Check for Mach-O magic by reading just 4 bytes
            guard isMachO(path: fileURL.path) else { continue }

            guard var binaryInfo = MachOParser.parse(url: fileURL) else { continue }

            // Enrich with code-signing info before detection and output
            VulnerabilityDetector.enrichWithCodeSigning(url: fileURL, info: &binaryInfo)

            let vulns = VulnerabilityDetector.check(binary: binaryInfo, executableURL: fileURL)
            vulnerabilities.append(contentsOf: vulns)

            let dlopenVulns = DlopenDetector.check(binary: binaryInfo, executableURL: fileURL)
            vulnerabilities.append(contentsOf: dlopenVulns)

            let deps = binaryInfo.loadCommands
                .filter { $0.type == .loadDylib || $0.type == .loadWeakDylib || $0.type == .reexportDylib }
                .map { $0.path }
            let rpaths = binaryInfo.loadCommands
                .filter { $0.type == .rpath }
                .map { $0.path }

            scannedBinaries.append(ScannedBinary(
                path: fileURL.path,
                fileType: binaryInfo.fileType.rawValue,
                arch: binaryInfo.parsedArchName,
                dependencies: deps,
                rpaths: rpaths,
                isHardenedRuntime: binaryInfo.isHardenedRuntime,
                isRestricted: binaryInfo.isRestricted,
                disablesLibraryValidation: binaryInfo.disablesLibraryValidation,
                isEncrypted: binaryInfo.isEncrypted,
                isApplePlatformBinary: binaryInfo.isApplePlatformBinary,
                teamID: binaryInfo.teamID,
                loadViability: binaryInfo.loadViability.rawValue
            ))

            count += 1
            if count % 100 == 0 {
                FileHandle.standardError.write("  ... scanned \(count) binaries\n".data(using: .utf8)!)
            }
        }

        return ScanResult(vulnerabilities: vulnerabilities, scannedBinaries: scannedBinaries)
    }

    private func isMachO(path: String) -> Bool {
        guard let fh = FileHandle(forReadingAtPath: path) else { return false }
        defer { fh.closeFile() }
        let data = fh.readData(ofLength: 4)
        guard data.count == 4 else { return false }
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        // FAT magic is big-endian on disk; UInt32 load on LE host byte-swaps
        return magic == 0xfeedfacf  // MH_MAGIC_64
            || magic == 0xfeedface  // MH_MAGIC
            || magic == 0xbebafeca  // FAT_MAGIC (0xcafebabe BE on disk)
            || magic == 0xbfbafeca  // FAT_MAGIC_64 (0xcafebabf BE on disk)
    }
}

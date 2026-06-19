import Foundation

// Detects runtime dlopen() targets that load-command walkers miss.
//
// dlopen's first argument is almost always a string literal living in
// __TEXT,__cstring. We extract those literals, keep the ones that look like
// dylib paths, and apply the same resolve + writability + load-viability gate
// the link-time detector uses. False positives (path-shaped strings that are
// never passed to dlopen) are filtered by requiring a writable hijack target.
class DlopenDetector {

    static func check(binary: BinaryInfo, executableURL: URL) -> [Vulnerability] {
        guard binary.cstringSize > 0 else { return [] }
        guard let data = try? Data(contentsOf: executableURL, options: .mappedIfSafe) else { return [] }

        let start = Int(binary.cstringOffset)
        let end = start + Int(binary.cstringSize)
        guard start >= 0, end <= data.count else { return [] }

        let strings = extractStrings(from: data[start..<end])
        guard !strings.isEmpty else { return [] }

        let viability = binary.loadViability
        let rpaths = binary.loadCommands.filter { $0.type == .rpath }.map { $0.path }
        // Paths already reported by the link-time detector — don't double-count.
        let loadCommandPaths = Set(binary.loadCommands.map { $0.path })

        var vulns: [Vulnerability] = []
        var reported = Set<String>()

        for candidate in strings {
            guard looksLikeDylibPath(candidate) else { continue }
            guard !loadCommandPaths.contains(candidate) else { continue }
            guard !reported.contains(candidate) else { continue }

            // Only resolvable forms produce an actionable hijack target.
            let resolvable = candidate.hasPrefix("/") || candidate.hasPrefix("@")
            guard resolvable else { continue }

            let possiblePaths = VulnerabilityDetector.expand(
                path: candidate, executableURL: executableURL, rpaths: rpaths
            )

            for resolvedURL in possiblePaths {
                let writableTarget: Bool
                if FileManager.default.fileExists(atPath: resolvedURL.path) {
                    writableTarget = VulnerabilityDetector.isWritable(path: resolvedURL.path)
                } else {
                    let parent = resolvedURL.deletingLastPathComponent()
                    writableTarget = VulnerabilityDetector.isWritable(path: parent.path)
                }
                guard writableTarget else { continue }

                let confidence: Confidence
                let severity: String
                switch viability {
                case .blocked:
                    confidence = .blocked
                    severity = "Info"
                case .sameTeamOnly:
                    confidence = .low
                    severity = "Low"
                case .loadable:
                    // Bare string match is LOW; upgrade to MEDIUM when the binary
                    // actually imports _dlopen, making it a plausible argument.
                    confidence = binary.importsDlopen ? .medium : .low
                    severity = binary.importsDlopen ? "Medium" : "Low"
                }

                let dlopenNote = binary.importsDlopen ? " (binary imports _dlopen)" : ""
                vulns.append(Vulnerability(
                    type: .dlopenRelative,
                    targetBinary: executableURL.path,
                    details: "Possible dlopen target '\(candidate)' resolves to writable \(resolvedURL.path)\(dlopenNote)",
                    severity: severity,
                    confidence: confidence,
                    loadViability: viability.rawValue
                ))
                reported.insert(candidate)
                break
            }
        }

        return vulns
    }

    // MARK: - String extraction

    private static func extractStrings(from slice: Data) -> [String] {
        var result: [String] = []
        var current: [UInt8] = []
        for byte in slice {
            if byte == 0 {
                if !current.isEmpty {
                    if let s = String(bytes: current, encoding: .utf8) { result.append(s) }
                    current.removeAll(keepingCapacity: true)
                }
            } else {
                current.append(byte)
            }
        }
        if !current.isEmpty, let s = String(bytes: current, encoding: .utf8) { result.append(s) }
        return result
    }

    private static func looksLikeDylibPath(_ s: String) -> Bool {
        guard s.count >= 4, s.count < 1024 else { return false }
        if s.hasSuffix(".dylib") || s.hasSuffix(".so") { return true }
        if s.contains(".framework/") { return true }
        // @-prefixed strings are candidate dlopen bases, but exclude ones with a
        // non-library file extension (e.g. .conf, .pem, .png) — those are data
        // files, not load targets. Keep directories (no extension) and .dylib/.so.
        if s.contains("@rpath") || s.contains("@loader_path") || s.contains("@executable_path") {
            let last = s.split(separator: "/").last.map(String.init) ?? s
            guard let dot = last.lastIndex(of: "."), last.index(after: dot) < last.endIndex else {
                return true // no extension → likely a directory base for dlopen
            }
            let ext = last[last.index(after: dot)...].lowercased()
            return ext == "dylib" || ext == "so"
        }
        return false
    }
}

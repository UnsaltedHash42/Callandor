import Foundation

// Rolls per-binary scan data up to the enclosing bundle and computes the
// weakest link — the strongest foothold an attacker has anywhere in the bundle.
// Library validation is enforced per-binary, so one LOADABLE binary undermines
// the whole bundle: a planted dylib it loads runs even if the main executable is
// fully hardened. This is the bundle-level view that a per-binary report misses.
class BundleAnalyzer {

    static func summarize(binaries: [ScannedBinary], vulns: [Vulnerability]) -> [BundleSummary] {
        var byBundle: [String: [ScannedBinary]] = [:]
        for b in binaries {
            byBundle[bundleRoot(for: b.path), default: []].append(b)
        }

        var hijackByBundle: [String: Int] = [:]
        for v in vulns where v.type != .envVarInjection {
            hijackByBundle[bundleRoot(for: v.targetBinary), default: 0] += 1
        }

        var summaries: [BundleSummary] = []
        for (bundle, bins) in byBundle {
            let loadable = bins.filter { $0.loadViability == "LOADABLE" }
            let sameTeam = bins.filter { $0.loadViability == "SAME_TEAM_ONLY" }
            let blocked = bins.filter { $0.loadViability == "BLOCKED" }

            let weakest: String
            if !loadable.isEmpty { weakest = "LOADABLE" }
            else if !sameTeam.isEmpty { weakest = "SAME_TEAM_ONLY" }
            else { weakest = "BLOCKED" }

            let footholds = loadable.prefix(8).map { b -> String in
                let rel = relative(b.path, to: bundle)
                return "\(rel) [\(footholdReason(b))]"
            }

            summaries.append(BundleSummary(
                bundle: bundle,
                binaryCount: bins.count,
                loadable: loadable.count,
                sameTeamOnly: sameTeam.count,
                blocked: blocked.count,
                weakestLink: weakest,
                footholds: Array(footholds),
                hijackFindings: hijackByBundle[bundle] ?? 0
            ))
        }

        // Most-exposed first: LOADABLE bundles with hijack findings on top.
        return summaries.sorted {
            if $0.weakestLink != $1.weakestLink { return rank($0.weakestLink) < rank($1.weakestLink) }
            return $0.hijackFindings > $1.hijackFindings
        }
    }

    private static func footholdReason(_ b: ScannedBinary) -> String {
        if !b.isHardenedRuntime { return "no-hardened-runtime" }
        if b.disablesLibraryValidation { return "disable-library-validation" }
        if b.allowsEnvVars { return "allow-dyld-env" }
        return "loadable"
    }

    private static func rank(_ viability: String) -> Int {
        switch viability {
        case "LOADABLE": return 0
        case "SAME_TEAM_ONLY": return 1
        default: return 2
        }
    }

    // Outermost .app wins (a nested helper .app rolls up to the app the user sees).
    static func bundleRoot(for path: String) -> String {
        if let r = path.range(of: ".app/") { return String(path[..<r.lowerBound]) + ".app" }
        if path.hasSuffix(".app") { return path }
        for ext in [".framework/", ".xpc/", ".bundle/", ".appex/", ".systemextension/"] {
            if let r = path.range(of: ext) {
                return String(path[..<r.lowerBound]) + String(ext.dropLast())
            }
        }
        return (path as NSString).deletingLastPathComponent
    }

    private static func relative(_ path: String, to bundle: String) -> String {
        path.hasPrefix(bundle) ? String(path.dropFirst(bundle.count)).drop(while: { $0 == "/" }).description : path
    }
}

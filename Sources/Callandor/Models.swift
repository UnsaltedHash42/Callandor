import Foundation

// MARK: - Mach-O file type (from mach_header.filetype)

enum MachOFileType: String, Encodable {
    case execute = "MH_EXECUTE"
    case dylib = "MH_DYLIB"
    case bundle = "MH_BUNDLE"
    case object = "MH_OBJECT"
    case unknown = "MH_UNKNOWN"

    init(raw: UInt32) {
        switch raw {
        case 0x2:  self = .execute
        case 0x6:  self = .dylib
        case 0x8:  self = .bundle
        case 0x1:  self = .object
        default:   self = .unknown
        }
    }
}

// MARK: - Load command types we care about

enum LoadCommandType: String, Encodable {
    case loadDylib = "LC_LOAD_DYLIB"
    case loadWeakDylib = "LC_LOAD_WEAK_DYLIB"
    case reexportDylib = "LC_REEXPORT_DYLIB"
    case idDylib = "LC_ID_DYLIB"
    case rpath = "LC_RPATH"
}

// MARK: - Dylib version info (from dylib_command)

struct DylibVersion: Encodable {
    let currentVersion: UInt32
    let compatVersion: UInt32

    var currentVersionString: String {
        Self.format(currentVersion)
    }

    var compatVersionString: String {
        Self.format(compatVersion)
    }

    private static func format(_ v: UInt32) -> String {
        let major = v >> 16
        let minor = (v >> 8) & 0xFF
        let patch = v & 0xFF
        return "\(major).\(minor).\(patch)"
    }
}

// MARK: - A single load command extracted from the binary

struct LoadCommandInfo: Encodable {
    let type: LoadCommandType
    let path: String
    var version: DylibVersion?
}

// MARK: - Per-slice parsed info

struct SliceInfo {
    let cpuType: UInt32
    let cpuSubtype: UInt32
    let offset: UInt64
    let size: UInt64
    let is64Bit: Bool
}

// MARK: - Code-signing load viability

enum LoadViability: String, Encodable {
    case loadable = "LOADABLE"
    case blocked = "BLOCKED"
    case sameTeamOnly = "SAME_TEAM_ONLY"
}

struct BinaryInfo {
    let url: URL
    var fileType: MachOFileType = .unknown
    var loadCommands: [LoadCommandInfo] = []
    var isRestricted: Bool = false
    var isHardenedRuntime: Bool = false
    var allowsEnvVars: Bool = false
    var disablesLibraryValidation: Bool = false
    var isApplePlatformBinary: Bool = false
    var isEncrypted: Bool = false
    var isSetuid: Bool = false
    var isSetgid: Bool = false
    var teamID: String? = nil
    var slices: [SliceInfo] = []
    var parsedArchName: String = "unknown"
    // __TEXT,__cstring bounds (absolute file offset into the on-disk Data)
    var cstringOffset: UInt64 = 0
    var cstringSize: UInt64 = 0
    var importsDlopen: Bool = false

    var loadViability: LoadViability {
        if isApplePlatformBinary { return .blocked }
        if isEncrypted { return .blocked }
        if isHardenedRuntime && !disablesLibraryValidation { return .sameTeamOnly }
        return .loadable
    }
}

// MARK: - Confidence tier for findings

enum Confidence: String, Encodable {
    case confirmed = "CONFIRMED"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case blocked = "BLOCKED"
}

// MARK: - Scan output models

enum VulnerabilityType: String, Encodable {
    case weakDylibHijack
    case rpathHijack
    case relativePath
    case envVarInjection
    case dlopenRelative
}

struct Vulnerability: Encodable {
    let type: VulnerabilityType
    let targetBinary: String
    let details: String
    let severity: String
    let confidence: Confidence
    let loadViability: String
}

struct ScanResult: Encodable {
    var vulnerabilities: [Vulnerability]
    var scannedBinaries: [ScannedBinary]
}

struct ScannedBinary: Encodable {
    let path: String
    let fileType: String
    let arch: String
    let dependencies: [String]
    let rpaths: [String]
    let isHardenedRuntime: Bool
    let isRestricted: Bool
    let disablesLibraryValidation: Bool
    let isEncrypted: Bool
    let isApplePlatformBinary: Bool
    let teamID: String?
    let loadViability: String
}

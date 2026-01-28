import Foundation

enum VulnerabilityType: String, Encodable {
    case weakDylibMissing
    case writableRpath
    case relativePath
    case envVarInjection
}

struct Vulnerability: Encodable {
    let type: VulnerabilityType
    let targetBinary: String
    let details: String
    let severity: String
}

struct ScanResult: Encodable {
    var vulnerabilities: [Vulnerability]
    var scannedBinaries: [ScannedBinary]
}

struct ScannedBinary: Encodable {
    let path: String
    let dependencies: [String]
    let rpaths: [String]
}

struct BinaryInfo {
    let url: URL
    var loadCommands: [LoadCommandInfo] = []
    var isRestricted: Bool = false
    var isHardenedRuntime: Bool = false
    var allowsEnvVars: Bool = false
    var rpaths: [String] = []
}

enum LoadCommandType {
    case loadDylib
    case loadWeakDylib
    case rpath
    case unknown
}

struct LoadCommandInfo {
    let type: LoadCommandType
    let path: String
}

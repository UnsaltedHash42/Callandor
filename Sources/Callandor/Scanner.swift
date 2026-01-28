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
        
        // Helper to check if file is Mach-O
        func isMachO(url: URL) -> Bool {
            guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return false }
            if data.count < 4 { return false }
            let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
            return magic == 0xfeedfacf || magic == 0xfeedface || magic == 0xcafebabe
        }
        
        print("Starting scan of \(path)...")
        
        let enumerator = fileManager.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsPackageDescendants, .skipsHiddenFiles])
        
        // Skip first pass since we want deep scan anyway
        
        // Re-create enumerator without skipping packages
        if let deepEnumerator = fileManager.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) {
            while let fileURL = deepEnumerator.nextObject() as? URL {
                
                // Exclude common non-binaries
                let ext = fileURL.pathExtension.lowercased()
                if ["png", "jpg", "plist", "json", "txt", "md", "h", "swift", "c", "html", "css", "nib", "strings", "car"].contains(ext) {
                    continue
                }
                
                if isMachO(url: fileURL) {
                    if let binaryInfo = MachOParser.parse(url: fileURL) {
                        let vulns = VulnerabilityDetector.check(binary: binaryInfo, executableURL: fileURL)
                        vulnerabilities.append(contentsOf: vulns)
                        
                        // Record binary info
                        let deps = binaryInfo.loadCommands.filter { $0.type == .loadDylib || $0.type == .loadWeakDylib }.map { $0.path }
                        let rpaths = binaryInfo.loadCommands.filter { $0.type == .rpath }.map { $0.path }
                        
                        scannedBinaries.append(ScannedBinary(path: fileURL.path, dependencies: deps, rpaths: rpaths))
                    }
                }
            }
        }
        
        return ScanResult(vulnerabilities: vulnerabilities, scannedBinaries: scannedBinaries)
    }
}

import Foundation
import MachO

class MachOParser {
    
    static func parse(url: URL) -> BinaryInfo? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        
        // Basic check for Magic Bytes
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        
        // Handle variations (FAT, 64-bit, etc). For this simple tool, we focus on thinning to the host architecture or just parsing the first slice if it's FAT, 
        // but robustly we should probably look for the arm64 slice on Apple Silicon.
        
        // For simplicity in this first iteration, let's assume single arch or just check headers.
        // In reality, we'd need to parse FAT headers.
        
        var info = BinaryInfo(url: url)
        
        // This is a naive implementation that expects a thin binary or header at 0. 
        // TODO: Add FAT binary support to find the relevant slice.
        
        // Use a pointer scanner
        data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            guard let basePtr = buffer.baseAddress else { return }
            
            let header = basePtr.bindMemory(to: mach_header_64.self, capacity: 1).pointee
            
            // Check magic for 64-bit Mach-O (MH_MAGIC_64 = 0xfeedfacf)
            let MH_MAGIC_64: UInt32 = 0xfeedfacf
            if header.magic != MH_MAGIC_64 {
                // Try FAT?
                // For now, return nil if not 64-bit macho.
                return 
            }
            
            // Iterate Load Commands
            var commandPtr = basePtr.advanced(by: MemoryLayout<mach_header_64>.size)
            
            for _ in 0..<header.ncmds {
                let command = commandPtr.bindMemory(to: load_command.self, capacity: 1).pointee
                
                switch command.cmd {
                case UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB): // Standard and Weak dylibs
                    let dylibCmd = commandPtr.bindMemory(to: dylib_command.self, capacity: 1).pointee
                    // Path offset is relative to the start of the command
                    let pathOffset = Int(dylibCmd.dylib.name.offset)
                    if let pathString = String(validatingCString: commandPtr.advanced(by: pathOffset).bindMemory(to: CChar.self, capacity: 1024)) {
                         let type: LoadCommandType = (command.cmd == UInt32(LC_LOAD_WEAK_DYLIB)) ? .loadWeakDylib : .loadDylib
                         info.loadCommands.append(LoadCommandInfo(type: type, path: pathString))
                    }
                    
                case UInt32(LC_RPATH):
                    let rpathCmd = commandPtr.bindMemory(to: rpath_command.self, capacity: 1).pointee
                    let pathOffset = Int(rpathCmd.path.offset)
                    if let pathString = String(validatingCString: commandPtr.advanced(by: pathOffset).bindMemory(to: CChar.self, capacity: 1024)) {
                         info.loadCommands.append(LoadCommandInfo(type: .rpath, path: pathString))
                    }
                    
                case UInt32(LC_CODE_SIGNATURE):
                    // In a real implementation we would parse the CS blob here for entitlements and flags.
                    // For now, we will use the `codesign` CLI as a fallback or implement deep CSBlob parsing later if time permits,
                    // as CSBlob parsing is complex.
                    // However, we can read the `cpusubtype` or dynamic headers.
                    break
                    
                default:
                    break
                }
                
                commandPtr = commandPtr.advanced(by: Int(command.cmdsize))
            }
            
            // Check for __RESTRICT segment
            // This requires parsing LC_SEGMENT_64
            // We'll do a second pass or integrate it into the first loop.
        }
        
        // Re-scan for segments to find checks
        data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            guard let basePtr = buffer.baseAddress else { return }
            let header = basePtr.bindMemory(to: mach_header_64.self, capacity: 1).pointee
            if header.magic != 0xfeedfacf { return }

            var commandPtr = basePtr.advanced(by: MemoryLayout<mach_header_64>.size)
            
            for _ in 0..<header.ncmds {
                let command = commandPtr.bindMemory(to: load_command.self, capacity: 1).pointee
                
                if command.cmd == UInt32(LC_SEGMENT_64) {
                     let segmentCmd = commandPtr.bindMemory(to: segment_command_64.self, capacity: 1).pointee
                     
                     // Helper to read fixed size char array
                     let segName = withUnsafeBytes(of: segmentCmd.segname) {
                         String(data: Data($0), encoding: .utf8)?.trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? ""
                     }
                    
                    if segName == "__RESTRICT" {
                        // technically we should check for section "__restrict" too, but the segment existence is a strong indicator.
                        info.isRestricted = true
                    }
                }
                 commandPtr = commandPtr.advanced(by: Int(command.cmdsize))
            }
        }
        
        
        return info
    }
}

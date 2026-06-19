import Foundation
import MachO

class MachOParser {

    // FAT magic is big-endian on disk; on a LE host UInt32 reads byte-swapped.
    private static let FAT_MAGIC: UInt32    = 0xbebafeca  // 0xcafebabe BE on disk
    private static let FAT_MAGIC_64: UInt32 = 0xbfbafeca  // 0xcafebabf BE on disk
    private static let MH_MAGIC_32: UInt32  = 0xfeedface
    private static let MH_MAGIC_64: UInt32  = 0xfeedfacf

    static func parse(url: URL) -> BinaryInfo? {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        guard data.count >= 4 else { return nil }

        var info = BinaryInfo(url: url)

        // Check setuid/setgid
        if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           let posix = attrs[.posixPermissions] as? Int {
            info.isSetuid = (posix & 0o4000) != 0
            info.isSetgid = (posix & 0o2000) != 0
        }

        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }

        if magic == FAT_MAGIC || magic == FAT_MAGIC_64 {
            return parseFAT(data: data, info: &info)
        } else if magic == MH_MAGIC_64 || magic == MH_MAGIC_32 {
            return parseThin(data: data, offset: 0, info: &info)
        }

        return nil
    }

    // MARK: - FAT / Universal

    private static func parseFAT(data: Data, info: inout BinaryInfo) -> BinaryInfo? {
        guard data.count >= 8 else { return nil }

        return data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> BinaryInfo? in
            guard let base = buffer.baseAddress else { return nil }

            let magic = base.load(as: UInt32.self)
            let is64Fat = (magic == FAT_MAGIC_64)

            // FAT header stores nfat_arch in big-endian
            let nArch = UInt32(bigEndian: base.advanced(by: 4).load(as: UInt32.self))
            guard nArch > 0, nArch < 256 else { return nil } // sanity cap

            let archEntrySize = is64Fat ? 32 : 20 // fat_arch_64 vs fat_arch
            let headerEnd = 8 + Int(nArch) * archEntrySize
            guard data.count >= headerEnd else { return nil }

            var slices: [SliceInfo] = []
            var nativeSliceOffset: UInt64? = nil
            var nativeSliceSize: UInt64? = nil

            for i in 0..<Int(nArch) {
                let entryPtr = base.advanced(by: 8 + i * archEntrySize)

                let cpuType: UInt32
                let cpuSubtype: UInt32
                let offset: UInt64
                let size: UInt64

                if is64Fat {
                    cpuType    = UInt32(bigEndian: entryPtr.load(as: UInt32.self))
                    cpuSubtype = UInt32(bigEndian: entryPtr.advanced(by: 4).load(as: UInt32.self))
                    offset     = UInt64(bigEndian: entryPtr.advanced(by: 8).load(as: UInt64.self))
                    size       = UInt64(bigEndian: entryPtr.advanced(by: 16).load(as: UInt64.self))
                } else {
                    cpuType    = UInt32(bigEndian: entryPtr.load(as: UInt32.self))
                    cpuSubtype = UInt32(bigEndian: entryPtr.advanced(by: 4).load(as: UInt32.self))
                    offset     = UInt64(UInt32(bigEndian: entryPtr.advanced(by: 8).load(as: UInt32.self)))
                    size       = UInt64(UInt32(bigEndian: entryPtr.advanced(by: 12).load(as: UInt32.self)))
                }

                let sliceMagicOffset = Int(offset)
                guard sliceMagicOffset + 4 <= data.count else { continue }
                let sliceMagic = base.advanced(by: sliceMagicOffset).load(as: UInt32.self)
                let is64 = (sliceMagic == MH_MAGIC_64)

                let slice = SliceInfo(
                    cpuType: cpuType,
                    cpuSubtype: cpuSubtype,
                    offset: offset,
                    size: size,
                    is64Bit: is64
                )
                slices.append(slice)

                // Prefer arm64 (CPU_TYPE_ARM64 = 0x0100000C = 16777228)
                // Fall back to x86_64 (CPU_TYPE_X86_64 = 0x01000007 = 16777223)
                let CPU_TYPE_ARM64: UInt32  = 0x0100000C
                let CPU_TYPE_X86_64: UInt32 = 0x01000007

                if cpuType == CPU_TYPE_ARM64 {
                    nativeSliceOffset = offset
                    nativeSliceSize = size
                } else if cpuType == CPU_TYPE_X86_64 && nativeSliceOffset == nil {
                    nativeSliceOffset = offset
                    nativeSliceSize = size
                }
            }

            info.slices = slices

            guard let chosenOffset = nativeSliceOffset, let chosenSize = nativeSliceSize else {
                // No recognized arch slice — try first slice as fallback
                if let first = slices.first {
                    return parseThin(data: data, offset: Int(first.offset), info: &info)
                }
                return nil
            }

            guard Int(chosenOffset) + Int(chosenSize) <= data.count else { return nil }
            return parseThin(data: data, offset: Int(chosenOffset), info: &info)
        }
    }

    // MARK: - Thin (single-arch) Mach-O

    private static func parseThin(data: Data, offset: Int, info: inout BinaryInfo) -> BinaryInfo? {
        return data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> BinaryInfo? in
            guard let base = buffer.baseAddress else { return nil }
            let dataLen = buffer.count

            guard offset + 4 <= dataLen else { return nil }
            let magic = base.advanced(by: offset).load(as: UInt32.self)

            let is64: Bool
            let headerSize: Int

            switch magic {
            case MH_MAGIC_64:
                is64 = true
                headerSize = MemoryLayout<mach_header_64>.size
            case MH_MAGIC_32:
                is64 = false
                headerSize = MemoryLayout<mach_header>.size
            default:
                return nil
            }

            guard offset + headerSize <= dataLen else { return nil }

            let ncmds: UInt32
            let filetype: UInt32

            if is64 {
                let header = base.advanced(by: offset).load(as: mach_header_64.self)
                ncmds = header.ncmds
                filetype = header.filetype
                info.parsedArchName = archName(cpuType: header.cputype, cpuSubtype: header.cpusubtype)
            } else {
                let header = base.advanced(by: offset).load(as: mach_header.self)
                ncmds = header.ncmds
                filetype = header.filetype
                info.parsedArchName = archName(cpuType: header.cputype, cpuSubtype: header.cpusubtype)
            }

            info.fileType = MachOFileType(raw: filetype)
            guard ncmds > 0, ncmds < 10000 else { return nil } // sanity

            var cmdPtr = offset + headerSize
            let LC_LOAD_WEAK: UInt32    = UInt32(LC_LOAD_WEAK_DYLIB)
            let LC_LOAD: UInt32         = UInt32(LC_LOAD_DYLIB)
            let LC_RPATH_CMD: UInt32    = UInt32(LC_RPATH)
            let LC_SEG64: UInt32        = UInt32(LC_SEGMENT_64)
            let LC_SEG32: UInt32        = UInt32(LC_SEGMENT)
            let LC_REEXPORT: UInt32     = 0x1F | 0x80000000 // LC_REEXPORT_DYLIB
            let LC_ENCRYPT_64: UInt32   = 0x2C // LC_ENCRYPTION_INFO_64
            let LC_ENCRYPT_32: UInt32   = 0x21 // LC_ENCRYPTION_INFO

            for _ in 0..<ncmds {
                guard cmdPtr + 8 <= dataLen else { break }
                let cmd = base.advanced(by: cmdPtr).load(as: load_command.self)

                guard cmd.cmdsize >= 8, cmdPtr + Int(cmd.cmdsize) <= dataLen else { break }

                switch cmd.cmd {
                case LC_LOAD, LC_LOAD_WEAK, LC_REEXPORT:
                    if let path = readDylibPath(base: base, cmdPtr: cmdPtr, cmdSize: Int(cmd.cmdsize), dataLen: dataLen) {
                        let type: LoadCommandType
                        switch cmd.cmd {
                        case LC_LOAD_WEAK: type = .loadWeakDylib
                        case LC_REEXPORT:  type = .reexportDylib
                        default:           type = .loadDylib
                        }

                        var version: DylibVersion? = nil
                        if cmdPtr + MemoryLayout<dylib_command>.size <= dataLen {
                            let dylibCmd = base.advanced(by: cmdPtr).load(as: dylib_command.self)
                            version = DylibVersion(
                                currentVersion: dylibCmd.dylib.current_version,
                                compatVersion: dylibCmd.dylib.compatibility_version
                            )
                        }

                        info.loadCommands.append(LoadCommandInfo(type: type, path: path, version: version))
                    }

                case LC_RPATH_CMD:
                    if let path = readRpathPath(base: base, cmdPtr: cmdPtr, cmdSize: Int(cmd.cmdsize), dataLen: dataLen) {
                        info.loadCommands.append(LoadCommandInfo(type: .rpath, path: path))
                    }

                case LC_SEG64:
                    guard cmdPtr + MemoryLayout<segment_command_64>.size <= dataLen else { break }
                    let seg = base.advanced(by: cmdPtr).load(as: segment_command_64.self)
                    let segName = readSegmentName64(seg)
                    if segName == "__RESTRICT" {
                        info.isRestricted = true
                    }

                case LC_SEG32:
                    guard cmdPtr + MemoryLayout<segment_command>.size <= dataLen else { break }
                    let seg = base.advanced(by: cmdPtr).load(as: segment_command.self)
                    let segName = readSegmentName32(seg)
                    if segName == "__RESTRICT" {
                        info.isRestricted = true
                    }

                case LC_ENCRYPT_64:
                    guard cmdPtr + 24 <= dataLen else { break }
                    // cryptid at offset 16 in encryption_info_command_64
                    let cryptid = base.advanced(by: cmdPtr + 16).load(as: UInt32.self)
                    if cryptid != 0 { info.isEncrypted = true }

                case LC_ENCRYPT_32:
                    guard cmdPtr + 20 <= dataLen else { break }
                    let cryptid = base.advanced(by: cmdPtr + 16).load(as: UInt32.self)
                    if cryptid != 0 { info.isEncrypted = true }

                default:
                    break
                }

                cmdPtr += Int(cmd.cmdsize)
            }

            return info
        }
    }

    // MARK: - String extraction helpers

    private static func readDylibPath(base: UnsafeRawPointer, cmdPtr: Int, cmdSize: Int, dataLen: Int) -> String? {
        guard cmdPtr + MemoryLayout<dylib_command>.size <= dataLen else { return nil }
        let dylibCmd = base.advanced(by: cmdPtr).load(as: dylib_command.self)
        let nameOffset = Int(dylibCmd.dylib.name.offset)
        guard nameOffset >= 0, nameOffset < cmdSize else { return nil }
        let stringStart = cmdPtr + nameOffset
        guard stringStart < dataLen else { return nil }
        let maxLen = min(cmdSize - nameOffset, dataLen - stringStart)
        return readCString(base: base, offset: stringStart, maxLen: maxLen)
    }

    private static func readRpathPath(base: UnsafeRawPointer, cmdPtr: Int, cmdSize: Int, dataLen: Int) -> String? {
        guard cmdPtr + MemoryLayout<rpath_command>.size <= dataLen else { return nil }
        let rpathCmd = base.advanced(by: cmdPtr).load(as: rpath_command.self)
        let pathOffset = Int(rpathCmd.path.offset)
        guard pathOffset >= 0, pathOffset < cmdSize else { return nil }
        let stringStart = cmdPtr + pathOffset
        guard stringStart < dataLen else { return nil }
        let maxLen = min(cmdSize - pathOffset, dataLen - stringStart)
        return readCString(base: base, offset: stringStart, maxLen: maxLen)
    }

    private static func readCString(base: UnsafeRawPointer, offset: Int, maxLen: Int) -> String? {
        guard maxLen > 0 else { return nil }
        let ptr = base.advanced(by: offset).bindMemory(to: UInt8.self, capacity: maxLen)
        var len = 0
        while len < maxLen && ptr[len] != 0 { len += 1 }
        guard len > 0 else { return nil }
        return String(bytes: UnsafeBufferPointer(start: ptr, count: len), encoding: .utf8)
    }

    private static func readSegmentName64(_ seg: segment_command_64) -> String {
        withUnsafeBytes(of: seg.segname) { buf in
            let data = Data(buf)
            return String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? ""
        }
    }

    private static func readSegmentName32(_ seg: segment_command) -> String {
        withUnsafeBytes(of: seg.segname) { buf in
            let data = Data(buf)
            return String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? ""
        }
    }

    private static func archName(cpuType: Int32, cpuSubtype: Int32) -> String {
        switch cpuType {
        case 0x0100000C: // CPU_TYPE_ARM64
            if cpuSubtype == 0x02 { return "arm64e" }
            return "arm64"
        case 0x0200000C: // CPU_TYPE_ARM64_32
            return "arm64_32"
        case 0x01000007: // CPU_TYPE_X86_64
            return "x86_64"
        case 0x0C:       // CPU_TYPE_ARM
            return "arm"
        case 0x07:       // CPU_TYPE_X86
            return "i386"
        default:
            return "unknown(\(cpuType))"
        }
    }
}

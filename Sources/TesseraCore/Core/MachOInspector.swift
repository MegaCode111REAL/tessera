import Foundation

/// What Tessera can learn from a Mach-O binary without executing it.
public struct MachOInfo: Equatable, Sendable {
    public var architectures: [String]
    /// True when an `LC_ENCRYPTION_INFO` command has a non-zero `cryptid` (FairPlay-encrypted).
    public var isEncrypted: Bool
    public var hasCodeSignature: Bool
    /// XML entitlements embedded in the code signature, if present.
    public var entitlementsXML: Data?

    public init(architectures: [String] = [], isEncrypted: Bool = false, hasCodeSignature: Bool = false, entitlementsXML: Data? = nil) {
        self.architectures = architectures
        self.isEncrypted = isEncrypted
        self.hasCodeSignature = hasCodeSignature
        self.entitlementsXML = entitlementsXML
    }
}

/// Minimal, bounds-checked Mach-O reader (thin and fat binaries).
public enum MachOInspector {
    /// Reads `length` bytes at `offset`, or `nil` if unavailable.
    public typealias Reader = (_ offset: UInt64, _ length: Int) -> Data?

    private static let lcCodeSignature: UInt32 = 0x1D
    private static let lcEncryptionInfo: UInt32 = 0x21
    private static let lcEncryptionInfo64: UInt32 = 0x2C
    private static let maxLoadCommandBytes = 1 << 20
    private static let maxSignatureBytes = 8 << 20

    /// Inspects a file on disk, reading only headers and the code-signature blob.
    /// Returns `nil` when the file is not a recognised Mach-O binary.
    public static func inspect(fileAt url: URL) -> MachOInfo? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        return inspect { offset, length in
            do {
                try handle.seek(toOffset: offset)
                return try handle.read(upToCount: length)
            } catch {
                return nil
            }
        }
    }

    public static func inspect(data: Data) -> MachOInfo? {
        inspect { offset, length in
            guard offset <= UInt64(data.count) else { return nil }
            let start = data.startIndex + Int(offset)
            let end = min(start + length, data.endIndex)
            return Data(data[start..<end])
        }
    }

    public static func inspect(reader: Reader) -> MachOInfo? {
        guard let magic = reader(0, 4), magic.count == 4 else { return nil }
        let bytes = [UInt8](magic)

        // Fat binaries use big-endian headers.
        if bytes == [0xCA, 0xFE, 0xBA, 0xBE] || bytes == [0xCA, 0xFE, 0xBA, 0xBF] {
            let is64 = bytes[3] == 0xBF
            guard let header = reader(4, 4), header.count == 4 else { return nil }
            let count = Int(be32(header, 0))
            guard count > 0, count <= 30 else { return nil }
            let entrySize = is64 ? 32 : 20
            guard let table = reader(8, count * entrySize), table.count == count * entrySize else { return nil }

            var result = MachOInfo()
            for index in 0..<count {
                let base = index * entrySize
                let sliceOffset: UInt64 = is64 ? be64(table, base + 8) : UInt64(be32(table, base + 8))
                guard let slice = inspectSlice(reader: reader, base: sliceOffset) else { continue }
                merge(&result, slice)
            }
            return result.architectures.isEmpty ? nil : result
        }

        return inspectSlice(reader: reader, base: 0)
    }

    private static func merge(_ result: inout MachOInfo, _ slice: MachOInfo) {
        result.architectures.append(contentsOf: slice.architectures)
        result.isEncrypted = result.isEncrypted || slice.isEncrypted
        result.hasCodeSignature = result.hasCodeSignature || slice.hasCodeSignature
        if result.entitlementsXML == nil { result.entitlementsXML = slice.entitlementsXML }
    }

    private static func inspectSlice(reader: Reader, base: UInt64) -> MachOInfo? {
        guard let header = reader(base, 32), header.count >= 28 else { return nil }
        let magic = [UInt8](header.prefix(4))
        let is64: Bool
        if magic == [0xCF, 0xFA, 0xED, 0xFE] {
            is64 = true
        } else if magic == [0xCE, 0xFA, 0xED, 0xFE] {
            is64 = false
        } else {
            return nil
        }
        let cpuType = le32(header, 4)
        let cpuSubtype = le32(header, 8)
        let commandCount = Int(le32(header, 16))
        let commandBytes = Int(le32(header, 20))
        let headerSize = is64 ? 32 : 28
        guard commandBytes > 0, commandBytes <= maxLoadCommandBytes, commandCount <= 4096 else {
            return MachOInfo(architectures: [architectureName(cpuType, cpuSubtype)])
        }
        guard let commands = reader(base + UInt64(headerSize), commandBytes), commands.count == commandBytes else {
            return MachOInfo(architectures: [architectureName(cpuType, cpuSubtype)])
        }

        var info = MachOInfo(architectures: [architectureName(cpuType, cpuSubtype)])
        var cursor = 0
        var signatureRange: (offset: UInt64, size: Int)?

        for _ in 0..<commandCount {
            guard cursor + 8 <= commands.count else { break }
            let command = le32(commands, cursor)
            let size = Int(le32(commands, cursor + 4))
            guard size >= 8, cursor + size <= commands.count else { break }

            switch command {
            case lcEncryptionInfo, lcEncryptionInfo64:
                if size >= 20, le32(commands, cursor + 16) != 0 { info.isEncrypted = true }
            case lcCodeSignature:
                if size >= 16 {
                    info.hasCodeSignature = true
                    let dataOffset = UInt64(le32(commands, cursor + 8))
                    let dataSize = Int(le32(commands, cursor + 12))
                    if dataSize > 0, dataSize <= maxSignatureBytes {
                        signatureRange = (base + dataOffset, dataSize)
                    }
                }
            default:
                break
            }
            cursor += size
        }

        if let range = signatureRange, let blob = reader(range.offset, range.size) {
            info.entitlementsXML = CodeSignatureReader.entitlementsXML(fromSuperBlob: blob)
        }
        return info
    }

    static func architectureName(_ cpuType: UInt32, _ cpuSubtype: UInt32) -> String {
        let subtype = cpuSubtype & 0x00FF_FFFF
        switch cpuType {
        case 0x0100_000C: return subtype == 2 ? "arm64e" : "arm64"
        case 0x0200_000C: return "arm64_32"
        case 0x0000_000C: return "arm"
        case 0x0100_0007: return "x86_64"
        case 0x0000_0007: return "i386"
        default: return String(format: "cpu(0x%08X)", cpuType)
        }
    }

    // MARK: - Byte helpers

    static func le32(_ data: Data, _ offset: Int) -> UInt32 {
        let base = data.startIndex + offset
        return UInt32(data[base])
            | UInt32(data[base + 1]) << 8
            | UInt32(data[base + 2]) << 16
            | UInt32(data[base + 3]) << 24
    }

    static func be32(_ data: Data, _ offset: Int) -> UInt32 {
        let base = data.startIndex + offset
        return UInt32(data[base]) << 24
            | UInt32(data[base + 1]) << 16
            | UInt32(data[base + 2]) << 8
            | UInt32(data[base + 3])
    }

    static func be64(_ data: Data, _ offset: Int) -> UInt64 {
        (UInt64(be32(data, offset)) << 32) | UInt64(be32(data, offset + 4))
    }
}

/// Reads the embedded-signature SuperBlob that follows `LC_CODE_SIGNATURE`.
public enum CodeSignatureReader {
    private static let superBlobMagic: UInt32 = 0xFADE_0CC0
    private static let entitlementsBlobMagic: UInt32 = 0xFADE_7171
    private static let entitlementsSlot: UInt32 = 5

    /// Extracts the XML entitlements blob, if the signature contains one.
    public static func entitlementsXML(fromSuperBlob blob: Data) -> Data? {
        guard blob.count >= 12, MachOInspector.be32(blob, 0) == superBlobMagic else { return nil }
        let count = Int(MachOInspector.be32(blob, 8))
        guard count >= 0, count <= 64, blob.count >= 12 + count * 8 else { return nil }

        for index in 0..<count {
            let entry = 12 + index * 8
            let slotType = MachOInspector.be32(blob, entry)
            let offset = Int(MachOInspector.be32(blob, entry + 4))
            guard slotType == entitlementsSlot, offset >= 0, offset + 8 <= blob.count else { continue }
            guard MachOInspector.be32(blob, offset) == entitlementsBlobMagic else { continue }
            let length = Int(MachOInspector.be32(blob, offset + 4))
            guard length >= 8, offset + length <= blob.count else { continue }
            let start = blob.startIndex + offset + 8
            let end = blob.startIndex + offset + length
            return Data(blob[start..<end])
        }
        return nil
    }
}

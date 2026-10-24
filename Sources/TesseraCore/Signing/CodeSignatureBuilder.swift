import Foundation

enum CSMagic {
    static let superBlob: UInt32 = 0xFADE_0CC0
    static let codeDirectory: UInt32 = 0xFADE_0C02
    static let requirements: UInt32 = 0xFADE_0C01
    static let entitlements: UInt32 = 0xFADE_7171
    static let derEntitlements: UInt32 = 0xFADE_7172
    static let cmsWrapper: UInt32 = 0xFADE_0B01
}

enum CSSlot {
    static let codeDirectory: UInt32 = 0
    static let infoPlist = 1
    static let requirements = 2
    static let codeResources = 3
    static let entitlements = 5
    static let derEntitlements = 7
    static let alternateCodeDirectory: UInt32 = 0x1000
    static let cms: UInt32 = 0x10000
}

/// Builders for the blobs that make up an embedded code signature.
enum CodeSignatureBuilder {
    static let pageSize = 4096
    static let codeDirectoryVersion: UInt32 = 0x20400
    static let adHocFlag: UInt32 = 0x2

    struct CodeDirectoryInput {
        var identifier: String
        var teamIdentifier: String?
        var hashKind: HashKind
        var flags: UInt32
        var pageHashes: [Data]
        var codeLimit: Int
        /// Special-slot hashes keyed by slot number (1 Info.plist, 2 requirements, 3 resources, 5 entitlements, 7 DER).
        var specialSlots: [Int: Data]
        var execSegmentBase: UInt64
        var execSegmentLimit: UInt64
        var execSegmentFlags: UInt64
    }

    /// An empty requirements set, which is what ad-hoc signatures carry.
    static let emptyRequirements: Data = {
        var writer = ByteWriter()
        writer.u32(CSMagic.requirements)
        writer.u32(12)
        writer.u32(0)
        return writer.data
    }()

    static func blob(magic: UInt32, payload: Data) -> Data {
        var writer = ByteWriter()
        writer.u32(magic)
        writer.u32(UInt32(8 + payload.count))
        writer.append(payload)
        return writer.data
    }

    static func codeDirectory(_ input: CodeDirectoryInput) -> Data {
        let hashSize = input.hashKind.size
        let identifier = Data(input.identifier.utf8) + Data([0])
        let team = input.teamIdentifier.map { Data($0.utf8) + Data([0]) }
        let specialCount = input.specialSlots.keys.max() ?? 0

        let headerSize = 88
        let identOffset = headerSize
        let teamOffset = team == nil ? 0 : identOffset + identifier.count
        let specialStart = identOffset + identifier.count + (team?.count ?? 0)
        let hashOffset = specialStart + specialCount * hashSize
        let total = hashOffset + input.pageHashes.count * hashSize

        var writer = ByteWriter()
        writer.u32(CSMagic.codeDirectory)
        writer.u32(UInt32(total))
        writer.u32(codeDirectoryVersion)
        writer.u32(input.flags)
        writer.u32(UInt32(hashOffset))
        writer.u32(UInt32(identOffset))
        writer.u32(UInt32(specialCount))
        writer.u32(UInt32(input.pageHashes.count))
        writer.u32(UInt32(input.codeLimit))
        writer.u8(UInt8(hashSize))
        writer.u8(input.hashKind.codeDirectoryType)
        writer.u8(0)            // platform
        writer.u8(12)           // log2(page size)
        writer.u32(0)           // spare2
        writer.u32(0)           // scatterOffset
        writer.u32(UInt32(teamOffset))
        writer.u32(0)           // spare3
        writer.u64(0)           // codeLimit64
        writer.u64(input.execSegmentBase)
        writer.u64(input.execSegmentLimit)
        writer.u64(input.execSegmentFlags)
        precondition(writer.count == headerSize, "CodeDirectory header must be 88 bytes")

        writer.append(identifier)
        if let team { writer.append(team) }
        if specialCount > 0 {
            for slot in stride(from: specialCount, through: 1, by: -1) {
                if let hash = input.specialSlots[slot], hash.count == hashSize {
                    writer.append(hash)
                } else {
                    writer.zeros(hashSize)
                }
            }
        }
        for hash in input.pageHashes { writer.append(hash) }
        precondition(writer.count == total, "CodeDirectory length mismatch")
        return writer.data
    }

    /// Wraps `slots` in a SuperBlob, zero-padded to `paddedTo` bytes when given.
    static func superBlob(slots: [(type: UInt32, blob: Data)], paddedTo: Int? = nil) -> Data {
        let ordered = slots.sorted { $0.type < $1.type }
        var offset = 12 + ordered.count * 8
        var index = ByteWriter()
        var body = ByteWriter()
        for slot in ordered {
            index.u32(slot.type)
            index.u32(UInt32(offset))
            body.append(slot.blob)
            offset += slot.blob.count
        }
        let natural = offset
        let total = max(natural, paddedTo ?? 0)

        var writer = ByteWriter()
        writer.u32(CSMagic.superBlob)
        writer.u32(UInt32(total))
        writer.u32(UInt32(ordered.count))
        writer.append(index.data)
        writer.append(body.data)
        writer.zeros(total - natural)
        return writer.data
    }
}

/// Everything that goes into one binary's signature besides its page hashes.
struct SignatureContent {
    var identifier: String
    var teamIdentifier: String?
    var entitlements: [String: PlistValue]?
    var infoPlist: Data?
    var codeResources: Data?
    var isAdHoc: Bool
    var codeLimit: Int
    var execSegmentBase: UInt64
    var execSegmentLimit: UInt64
    var isMainExecutable: Bool
}

/// Builds the full signature SuperBlob for one Mach-O slice.
enum SignatureAssembler {
    struct Built {
        var superBlob: Data
        /// The primary (SHA-1) and alternate (SHA-256) CodeDirectories, for the CMS signature.
        var primaryDirectory: Data
        var alternateDirectory: Data
    }

    /// - Parameters:
    ///   - pageHashes: `[kind: hashes of each 4 KiB page]`; the counts must match `ceil(codeLimit / 4096)`.
    ///   - cms: the CMS blob (already wrapped), or `nil` for an ad-hoc signature.
    ///   - totalSize: pads the SuperBlob to exactly this size (must not be smaller than the natural size).
    static func build(
        content: SignatureContent,
        sha1Pages: [Data],
        sha256Pages: [Data],
        cmsProvider: (_ primary: Data, _ alternate: Data) throws -> Data?,
        totalSize: Int? = nil
    ) throws -> Built {
        let requirements = CodeSignatureBuilder.emptyRequirements

        var entitlementsBlob: Data?
        var derBlob: Data?
        if let entitlements = content.entitlements, !entitlements.isEmpty {
            let xml = try PropertyListSerialization.data(
                fromPropertyList: entitlements.mapValues { $0.foundationObject },
                format: .xml,
                options: 0
            )
            entitlementsBlob = CodeSignatureBuilder.blob(magic: CSMagic.entitlements, payload: xml)
            derBlob = CodeSignatureBuilder.blob(
                magic: CSMagic.derEntitlements,
                payload: try EntitlementsDER.encode(entitlements)
            )
        }

        var flags: UInt64 = 0
        if content.isMainExecutable { flags |= 0x1 }                       // CS_EXECSEG_MAIN_BINARY
        if content.entitlements?["get-task-allow"]?.boolValue == true { flags |= 0x20 } // CS_EXECSEG_DEBUGGER

        func directory(_ kind: HashKind, pages: [Data]) -> Data {
            var special: [Int: Data] = [:]
            if let info = content.infoPlist { special[CSSlot.infoPlist] = kind.hash(info) }
            special[CSSlot.requirements] = kind.hash(requirements)
            if let resources = content.codeResources { special[CSSlot.codeResources] = kind.hash(resources) }
            if let blob = entitlementsBlob { special[CSSlot.entitlements] = kind.hash(blob) }
            if let blob = derBlob { special[CSSlot.derEntitlements] = kind.hash(blob) }
            return CodeSignatureBuilder.codeDirectory(.init(
                identifier: content.identifier,
                teamIdentifier: content.teamIdentifier,
                hashKind: kind,
                flags: content.isAdHoc ? CodeSignatureBuilder.adHocFlag : 0,
                pageHashes: pages,
                codeLimit: content.codeLimit,
                specialSlots: special,
                execSegmentBase: content.execSegmentBase,
                execSegmentLimit: content.execSegmentLimit,
                execSegmentFlags: flags
            ))
        }

        let primary = directory(.sha1, pages: sha1Pages)
        let alternate = directory(.sha256, pages: sha256Pages)

        var slots: [(type: UInt32, blob: Data)] = [
            (CSSlot.codeDirectory, primary),
            (UInt32(CSSlot.requirements), requirements),
        ]
        if let entitlementsBlob { slots.append((UInt32(CSSlot.entitlements), entitlementsBlob)) }
        if let derBlob { slots.append((UInt32(CSSlot.derEntitlements), derBlob)) }
        slots.append((CSSlot.alternateCodeDirectory, alternate))
        if let cms = try cmsProvider(primary, alternate) {
            slots.append((CSSlot.cms, CodeSignatureBuilder.blob(magic: CSMagic.cmsWrapper, payload: cms)))
        }

        let blob = CodeSignatureBuilder.superBlob(slots: slots, paddedTo: totalSize)
        if let totalSize, blob.count != totalSize {
            throw CodeSigningError.layout("The signature (\(blob.count) bytes) does not fit the reserved \(totalSize) bytes.")
        }
        return Built(superBlob: blob, primaryDirectory: primary, alternateDirectory: alternate)
    }
}

public enum CodeSigningError: Error, LocalizedError, Equatable {
    case notMachO(String)
    case unsupported(String)
    case layout(String)
    case key(String)
    case resources(String)

    public var errorDescription: String? {
        switch self {
        case .notMachO(let message): return message
        case .unsupported(let message): return message
        case .layout(let message): return message
        case .key(let message): return message
        case .resources(let message): return message
        }
    }
}

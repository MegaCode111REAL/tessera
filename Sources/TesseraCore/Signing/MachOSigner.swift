import Foundation

/// What goes into the signature of one executable.
public struct CodeSigningMaterials: Sendable {
    public var identifier: String
    public var teamIdentifier: String?
    /// Entitlements to embed (XML and DER), or `nil` for none.
    public var entitlements: [String: PlistValue]?
    /// Raw bytes of the bundle's `Info.plist` (special slot 1), if the binary belongs to a bundle.
    public var infoPlist: Data?
    /// Raw bytes of `_CodeSignature/CodeResources` (special slot 3).
    public var codeResources: Data?
    /// Signing key; `nil` produces an ad-hoc signature.
    public var key: CMSSigningKey?
    public var signingTime: Date

    public init(
        identifier: String,
        teamIdentifier: String? = nil,
        entitlements: [String: PlistValue]? = nil,
        infoPlist: Data? = nil,
        codeResources: Data? = nil,
        key: CMSSigningKey? = nil,
        signingTime: Date = Date()
    ) {
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.entitlements = entitlements
        self.infoPlist = infoPlist
        self.codeResources = codeResources
        self.key = key
        self.signingTime = signingTime
    }
}

/// Writes a code signature into Mach-O binaries (thin or fat, 64-bit).
public enum MachOSigner {
    private static let lcSegment64: UInt32 = 0x19
    private static let lcCodeSignature: UInt32 = 0x1D
    private static let machO64Magic: UInt32 = 0xFEED_FACF
    private static let pageSize = CodeSignatureBuilder.pageSize

    /// Signs `binary`, replacing any existing signature, and returns the new file contents.
    public static func sign(_ binary: Data, materials: CodeSigningMaterials) throws -> Data {
        let input = Data(binary)   // zero-based copy
        guard input.count >= 8 else { throw CodeSigningError.notMachO("The file is too small to be a Mach-O binary.") }

        if Bytes.be32(input, 0) == 0xCAFE_BABE {
            return try signFat(input, materials)
        }
        return try signSlice(input, materials)
    }

    // MARK: - Fat binaries

    struct FatArch {
        var cpuType: UInt32
        var cpuSubtype: UInt32
        var offset: Int
        var size: Int
        var align: UInt32
    }

    static func fatSlices(_ data: Data) throws -> [FatArch] {
        let count = Int(Bytes.be32(data, 4))
        guard count > 0, count <= 30, data.count >= 8 + count * 20 else {
            throw CodeSigningError.notMachO("The universal binary header is invalid.")
        }
        var out: [FatArch] = []
        for index in 0..<count {
            let base = 8 + index * 20
            let arch = FatArch(
                cpuType: Bytes.be32(data, base),
                cpuSubtype: Bytes.be32(data, base + 4),
                offset: Int(Bytes.be32(data, base + 8)),
                size: Int(Bytes.be32(data, base + 12)),
                align: Bytes.be32(data, base + 16)
            )
            guard arch.offset >= 0, arch.size > 0, arch.offset + arch.size <= data.count, arch.align <= 20 else {
                throw CodeSigningError.notMachO("A slice of the universal binary lies outside the file.")
            }
            out.append(arch)
        }
        return out
    }

    /// The thin slices of a binary (the whole file for thin binaries).
    static func slices(of data: Data) throws -> [Data] {
        let input = Data(data)
        guard input.count >= 8 else { throw CodeSigningError.notMachO("Too small.") }
        if Bytes.be32(input, 0) == 0xCAFE_BABE {
            return try fatSlices(input).map { Data(input[$0.offset..<($0.offset + $0.size)]) }
        }
        return [input]
    }

    private static func signFat(_ input: Data, _ materials: CodeSigningMaterials) throws -> Data {
        let arches = try fatSlices(input)
        var signed: [(arch: FatArch, data: Data)] = []
        for arch in arches {
            let slice = Data(input[arch.offset..<(arch.offset + arch.size)])
            signed.append((arch, try signSlice(slice, materials)))
        }

        var writer = ByteWriter()
        writer.u32(0xCAFE_BABE)
        writer.u32(UInt32(signed.count))
        var offset = 8 + signed.count * 20
        var layout: [(offset: Int, data: Data)] = []
        for entry in signed {
            offset = Bytes.alignUp(offset, 1 << Int(entry.arch.align))
            writer.u32(entry.arch.cpuType)
            writer.u32(entry.arch.cpuSubtype)
            writer.u32(UInt32(offset))
            writer.u32(UInt32(entry.data.count))
            writer.u32(entry.arch.align)
            layout.append((offset, entry.data))
            offset += entry.data.count
        }
        for item in layout {
            writer.zeros(item.offset - writer.count)
            writer.append(item.data)
        }
        return writer.data
    }

    // MARK: - Thin slices

    private static func signSlice(_ input: Data, _ materials: CodeSigningMaterials) throws -> Data {
        guard input.count >= 32, Bytes.le32(input, 0) == machO64Magic else {
            throw CodeSigningError.unsupported("Only 64-bit Mach-O binaries can be signed.")
        }

        var data = input
        let fileType = Bytes.le32(data, 12)
        var commandCount = Int(Bytes.le32(data, 16))
        var commandBytes = Int(Bytes.le32(data, 20))
        let commandsEnd = 32 + commandBytes
        guard commandBytes > 0, commandsEnd <= data.count, commandCount > 0, commandCount < 4096 else {
            throw CodeSigningError.notMachO("The Mach-O load commands are invalid.")
        }

        var textBase: UInt64 = 0
        var textLimit: UInt64 = 0
        var linkedit: (command: Int, fileOffset: Int, fileSize: Int)?
        var signatureCommand: Int?
        var signatureOffset = 0
        var signatureSize = 0
        var firstContentOffset = UInt64.max

        var cursor = 32
        for _ in 0..<commandCount {
            guard cursor + 8 <= commandsEnd else { throw CodeSigningError.notMachO("Truncated load command.") }
            let command = Bytes.le32(data, cursor)
            let size = Int(Bytes.le32(data, cursor + 4))
            guard size >= 8, cursor + size <= commandsEnd else { throw CodeSigningError.notMachO("Invalid load command size.") }

            if command == lcSegment64, size >= 72 {
                let name = Bytes.cString(data, cursor + 8, maxLength: 16)
                let fileOffset = Bytes.le64(data, cursor + 40)
                let fileSize = Bytes.le64(data, cursor + 48)
                let sectionCount = Int(Bytes.le32(data, cursor + 64))
                if name == "__TEXT" {
                    textBase = fileOffset
                    textLimit = fileSize
                } else if name == "__LINKEDIT" {
                    linkedit = (cursor, Int(fileOffset), Int(fileSize))
                }
                for section in 0..<min(sectionCount, 255) {
                    let base = cursor + 72 + section * 80
                    guard base + 80 <= cursor + size else { break }
                    let sectionOffset = UInt64(Bytes.le32(data, base + 48))
                    if sectionOffset != 0 { firstContentOffset = min(firstContentOffset, sectionOffset) }
                }
            } else if command == lcCodeSignature, size >= 16 {
                signatureCommand = cursor
                signatureOffset = Int(Bytes.le32(data, cursor + 8))
                signatureSize = Int(Bytes.le32(data, cursor + 12))
            }
            cursor += size
        }

        guard let linkedit else { throw CodeSigningError.notMachO("The binary has no __LINKEDIT segment.") }

        // Remove an existing signature (it must be the last thing in the file).
        let signatureCommandOffset: Int
        if let existing = signatureCommand {
            guard signatureOffset >= linkedit.fileOffset, signatureOffset + signatureSize == data.count else {
                throw CodeSigningError.layout("The existing signature is not at the end of the file, so it cannot be replaced safely.")
            }
            data = Data(data.prefix(signatureOffset))
            signatureCommandOffset = existing
        } else {
            guard linkedit.fileOffset + linkedit.fileSize == data.count else {
                throw CodeSigningError.layout("The file has data after __LINKEDIT, so a signature cannot be appended safely.")
            }
            // A new LC_CODE_SIGNATURE needs 16 free bytes after the load commands.
            guard UInt64(commandsEnd + 16) <= firstContentOffset else {
                throw CodeSigningError.layout("There is no room in the Mach-O header for a signature command. Rebuild the binary with -headerpad.")
            }
            Bytes.putLE32(&data, commandsEnd, lcCodeSignature)
            Bytes.putLE32(&data, commandsEnd + 4, 16)
            commandCount += 1
            commandBytes += 16
            Bytes.putLE32(&data, 16, UInt32(commandCount))
            Bytes.putLE32(&data, 20, UInt32(commandBytes))
            signatureCommandOffset = commandsEnd
        }

        // Align and pad so the signature starts on a 16-byte boundary.
        let newSignatureOffset = Bytes.alignUp(data.count, 16)
        data.append(Data(count: newSignatureOffset - data.count))
        let codeLimit = newSignatureOffset
        let pageCount = (codeLimit + pageSize - 1) / pageSize

        let content = SignatureContent(
            identifier: materials.identifier,
            teamIdentifier: materials.teamIdentifier,
            entitlements: materials.entitlements,
            infoPlist: materials.infoPlist,
            codeResources: materials.codeResources,
            isAdHoc: materials.key == nil,
            codeLimit: codeLimit,
            execSegmentBase: textBase,
            execSegmentLimit: textLimit,
            isMainExecutable: fileType == 2
        )

        // Pass 1: measure. The header (hashed below) records the signature size, so it must be known first.
        let zeroSHA1 = Array(repeating: Data(count: HashKind.sha1.size), count: pageCount)
        let zeroSHA256 = Array(repeating: Data(count: HashKind.sha256.size), count: pageCount)
        let key = materials.key
        let reservedCMS = key.map { CMSBuilder.estimatedSize(for: $0) + 512 } ?? 0
        let measured = try SignatureAssembler.build(
            content: content,
            sha1Pages: zeroSHA1,
            sha256Pages: zeroSHA256,
            cmsProvider: { _, _ in key == nil ? nil : Data(count: reservedCMS) }
        )
        let signatureSizeFinal = Bytes.alignUp(measured.superBlob.count, 16)

        // Patch the header: signature command and __LINKEDIT sizes.
        Bytes.putLE32(&data, signatureCommandOffset + 8, UInt32(newSignatureOffset))
        Bytes.putLE32(&data, signatureCommandOffset + 12, UInt32(signatureSizeFinal))
        let linkeditFileSize = newSignatureOffset + signatureSizeFinal - linkedit.fileOffset
        Bytes.putLE64(&data, linkedit.command + 48, UInt64(linkeditFileSize))
        Bytes.putLE64(&data, linkedit.command + 32, UInt64(Bytes.alignUp(linkeditFileSize, 0x4000)))

        // Pass 2: hash every page of the patched file and build the real signature.
        var sha1Pages: [Data] = []
        var sha256Pages: [Data] = []
        sha1Pages.reserveCapacity(pageCount)
        sha256Pages.reserveCapacity(pageCount)
        var offset = 0
        while offset < codeLimit {
            let end = min(offset + pageSize, codeLimit)
            let page = data[offset..<end]
            sha1Pages.append(HashKind.sha1.hash(Data(page)))
            sha256Pages.append(HashKind.sha256.hash(Data(page)))
            offset = end
        }

        let signingTime = materials.signingTime
        let built = try SignatureAssembler.build(
            content: content,
            sha1Pages: sha1Pages,
            sha256Pages: sha256Pages,
            cmsProvider: { primary, alternate in
                guard let key else { return nil }
                let cms = try CMSBuilder.build(primaryDirectory: primary, alternateDirectory: alternate, key: key, signingTime: signingTime)
                guard cms.count <= reservedCMS else {
                    throw CodeSigningError.layout("The CMS signature (\(cms.count) bytes) is larger than the reserved space (\(reservedCMS)).")
                }
                return cms
            },
            totalSize: measured.superBlob.count
        )
        data.append(built.superBlob)
        data.append(Data(count: signatureSizeFinal - built.superBlob.count))
        return data
    }
}

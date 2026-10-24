import Foundation

/// Re-reads signatures from disk and checks them against the files they cover.
/// This is an internal-consistency check (hashes, special slots, resources); it does not
/// validate the certificate chain, which iOS does at install time.
public enum SignatureVerifier {
    public static func verify(appBundle: URL, plan: SigningPlan) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        for step in plan.steps {
            let url = step.isMainApp ? appBundle : appBundle.appendingPathComponent(step.relativePath)
            if step.kind == .dynamicLibrary {
                issues += verifyBinary(url, label: step.displayName, expectedIdentifier: nil, infoPlist: nil, codeResources: nil)
                continue
            }
            guard let info = try? Data(contentsOf: url.appendingPathComponent("Info.plist")),
                  let object = try? PropertyListSerialization.propertyList(from: info, options: [], format: nil),
                  let dict = object as? [String: Any],
                  let executable = dict["CFBundleExecutable"] as? String else {
                issues.append(.init(code: "SIGNATURE_BUNDLE", severity: .error, message: "\(step.displayName): Info.plist or executable name is unreadable."))
                continue
            }
            let resources = try? Data(contentsOf: url.appendingPathComponent("_CodeSignature/CodeResources"))
            issues += verifyBinary(
                url.appendingPathComponent(executable),
                label: step.displayName,
                expectedIdentifier: dict["CFBundleIdentifier"] as? String,
                infoPlist: info,
                codeResources: resources
            )
            for problem in CodeResourcesBuilder.verify(bundle: url, executableName: executable) {
                issues.append(.init(code: "RESOURCE_MISMATCH", severity: .error, message: "\(step.displayName): \(problem)"))
            }
        }
        return issues
    }

    static func verifyBinary(
        _ url: URL,
        label: String,
        expectedIdentifier: String?,
        infoPlist: Data?,
        codeResources: Data?
    ) -> [ValidationIssue] {
        func error(_ code: String, _ message: String) -> ValidationIssue {
            .init(code: code, severity: .error, message: "\(label): \(message)")
        }
        guard let data = try? Data(contentsOf: url), let slices = try? MachOSigner.slices(of: data) else {
            return [error("SIGNATURE_MISSING", "the executable could not be read.")]
        }
        var issues: [ValidationIssue] = []
        for slice in slices {
            guard slice.count >= 32, Bytes.le32(slice, 0) == 0xFEED_FACF else {
                issues.append(error("SIGNATURE_MISSING", "a slice is not a 64-bit Mach-O binary."))
                continue
            }
            var offset = 0, size = 0, found = false
            var cursor = 32
            let end = 32 + Int(Bytes.le32(slice, 20))
            guard end <= slice.count else { issues.append(error("SIGNATURE_MISSING", "the load commands are truncated.")); continue }
            for _ in 0..<Int(Bytes.le32(slice, 16)) {
                guard cursor + 8 <= end else { break }
                let command = Bytes.le32(slice, cursor)
                let length = Int(Bytes.le32(slice, cursor + 4))
                guard length >= 8, cursor + length <= end else { break }
                if command == 0x1D, length >= 16 {
                    found = true
                    offset = Int(Bytes.le32(slice, cursor + 8))
                    size = Int(Bytes.le32(slice, cursor + 12))
                }
                cursor += length
            }
            guard found, size >= 20, offset + size <= slice.count else {
                issues.append(error("SIGNATURE_MISSING", "the executable has no code signature."))
                continue
            }
            issues += verifySignature(
                slice: slice, offset: offset, size: size, label: label,
                expectedIdentifier: expectedIdentifier, infoPlist: infoPlist, codeResources: codeResources
            )
        }
        return issues
    }

    private static func verifySignature(
        slice: Data, offset: Int, size: Int, label: String,
        expectedIdentifier: String?, infoPlist: Data?, codeResources: Data?
    ) -> [ValidationIssue] {
        func error(_ code: String, _ message: String) -> ValidationIssue {
            .init(code: code, severity: .error, message: "\(label): \(message)")
        }
        let blob = Data(slice[offset..<(offset + size)])
        guard Bytes.be32(blob, 0) == CSMagic.superBlob else { return [error("SIGNATURE_FORMAT", "the signature is not a SuperBlob.")] }
        let count = Int(Bytes.be32(blob, 8))
        guard count > 0, count < 32, blob.count >= 12 + count * 8 else { return [error("SIGNATURE_FORMAT", "the SuperBlob index is invalid.")] }

        var entries: [(type: UInt32, offset: Int)] = []
        for index in 0..<count {
            entries.append((Bytes.be32(blob, 12 + index * 8), Int(Bytes.be32(blob, 16 + index * 8))))
        }
        func slot(_ type: UInt32) -> Data? {
            guard let entry = entries.first(where: { $0.type == type }), entry.offset + 8 <= blob.count else { return nil }
            let length = Int(Bytes.be32(blob, entry.offset + 4))
            guard length >= 8, entry.offset + length <= blob.count else { return nil }
            return Data(blob[entry.offset..<(entry.offset + length)])
        }

        var issues: [ValidationIssue] = []
        let requirements = slot(UInt32(CSSlot.requirements))
        let entitlements = slot(UInt32(CSSlot.entitlements))
        let der = slot(UInt32(CSSlot.derEntitlements))

        guard slot(CSSlot.codeDirectory) != nil else { return [error("SIGNATURE_FORMAT", "no CodeDirectory.")] }
        for type in [CSSlot.codeDirectory, CSSlot.alternateCodeDirectory] {
            guard let directory = slot(type) else { continue }
            guard directory.count >= 44, Bytes.be32(directory, 0) == CSMagic.codeDirectory else {
                issues.append(error("SIGNATURE_FORMAT", "a CodeDirectory is malformed."))
                continue
            }
            let hashOffset = Int(Bytes.be32(directory, 16))
            let identOffset = Int(Bytes.be32(directory, 20))
            let specialCount = Int(Bytes.be32(directory, 24))
            let codeCount = Int(Bytes.be32(directory, 28))
            let codeLimit = Int(Bytes.be32(directory, 32))
            let hashSize = Int(directory[directory.startIndex + 36])
            let hashType = directory[directory.startIndex + 37]
            let kind: HashKind = hashType == 1 ? .sha1 : .sha256
            guard (hashType == 1 || hashType == 2), hashSize == kind.size,
                  hashOffset - specialCount * hashSize >= 0,
                  hashOffset + codeCount * hashSize <= directory.count, identOffset < directory.count else {
                issues.append(error("SIGNATURE_FORMAT", "a CodeDirectory has an invalid layout."))
                continue
            }
            if codeLimit != offset || codeCount != (codeLimit + 4095) / 4096 {
                issues.append(error("SIGNATURE_PAGE_HASH", "the CodeDirectory covers \(codeLimit) bytes but the signature starts at \(offset)."))
                continue
            }
            let identifier = Bytes.cString(directory, identOffset, maxLength: directory.count - identOffset)
            if let expectedIdentifier, identifier != expectedIdentifier {
                issues.append(error("SIGNATURE_IDENTIFIER", "the signature identifier “\(identifier)” does not match “\(expectedIdentifier)”."))
            }
            for page in 0..<codeCount {
                let start = page * 4096
                let stop = min(start + 4096, codeLimit)
                let expected = Data(directory[(hashOffset + page * hashSize)..<(hashOffset + (page + 1) * hashSize)])
                if kind.hash(Data(slice[start..<stop])) != expected {
                    issues.append(error("SIGNATURE_PAGE_HASH", "page \(page) of the executable does not match its recorded hash."))
                    break
                }
            }
            func special(_ number: Int) -> Data? {
                guard number <= specialCount else { return nil }
                let start = hashOffset - number * hashSize
                let value = Data(directory[start..<(start + hashSize)])
                return value.allSatisfy { $0 == 0 } ? nil : value
            }
            let checks: [(Int, String, Data?)] = [
                (CSSlot.infoPlist, "Info.plist", infoPlist),
                (CSSlot.requirements, "requirements", requirements),
                (CSSlot.codeResources, "CodeResources", codeResources),
                (CSSlot.entitlements, "entitlements", entitlements),
                (CSSlot.derEntitlements, "DER entitlements", der),
            ]
            for (number, name, actual) in checks {
                let recorded = special(number)
                if let actual {
                    if recorded != kind.hash(actual) {
                        issues.append(error("SIGNATURE_SPECIAL_SLOT", "the recorded hash of the \(name) does not match."))
                    }
                } else if recorded != nil, number != CSSlot.infoPlist || infoPlist != nil {
                    issues.append(error("SIGNATURE_SPECIAL_SLOT", "the signature records \(name) but it is missing."))
                }
            }
        }
        return issues
    }
}

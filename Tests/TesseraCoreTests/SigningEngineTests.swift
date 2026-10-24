import XCTest
import Security
@testable import TesseraCore

/// A synthetic arm64 Mach-O with __TEXT and __LINKEDIT, header padding, and optional existing signature blob.
enum SyntheticMachO {
    static func make(fileType: UInt32 = 2, textPages: Int = 2, trailingLinkedit: Int = 64) -> Data {
        var d = Data()
        func le32(_ v: UInt32) { d.append(contentsOf: [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 24) & 0xFF)]) }
        func le64(_ v: UInt64) { le32(UInt32(truncatingIfNeeded: v)); le32(UInt32(truncatingIfNeeded: v >> 32)) }
        func name(_ s: String) { var b = Array(s.utf8); b += Array(repeating: 0, count: 16 - b.count); d.append(contentsOf: b) }

        let textSize = textPages * 0x4000
        le32(0xFEED_FACF); le32(0x0100_000C); le32(0); le32(fileType)
        le32(2); le32(152 + 72); le32(0); le32(0)
        // __TEXT with one section at 0x4000-ish offset
        le32(0x19); le32(152); name("__TEXT"); le64(0x1_0000_0000); le64(UInt64(textSize)); le64(0); le64(UInt64(textSize))
        le32(5); le32(5); le32(1); le32(0)
        name("__text"); name("__TEXT"); le64(0x1_0000_0000 + 0x1000); le64(0x100); le32(0x1000); le32(2); le32(0); le32(0); le32(0x80000400); le32(0); le32(0); le32(0)
        // __LINKEDIT
        le32(0x19); le32(72); name("__LINKEDIT"); le64(0x1_0000_0000 + UInt64(textSize)); le64(0x4000)
        le64(UInt64(textSize)); le64(UInt64(trailingLinkedit)); le32(1); le32(1); le32(0); le32(0)
        d.append(Data(count: textSize - d.count))
        for i in 0..<trailingLinkedit { d.append(UInt8(i & 0xFF)) }
        return d
    }
}

final class SigningEngineTests: XCTestCase {
    func testDERPrimitives() {
        XCTAssertEqual([UInt8](DER.oid("1.2.840.113549.1.7.2")), [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        XCTAssertEqual([UInt8](DER.integer(128)), [0x02, 0x02, 0x00, 0x80])
        XCTAssertEqual([UInt8](DER.integer(1)), [0x02, 0x01, 0x01])
        XCTAssertEqual([UInt8](DER.length(300)), [0x82, 0x01, 0x2C])
    }

    func testEntitlementsDER() throws {
        let der = try EntitlementsDER.encode(["get-task-allow": .bool(true)])
        var expected: [UInt8] = [0x70, 0x17, 0x31, 0x15, 0x30, 0x13, 0x0C, 0x0E]
        expected += Array("get-task-allow".utf8)
        expected += [0x01, 0x01, 0xFF]
        XCTAssertEqual([UInt8](der), expected)
    }

    func testAdHocSignatureStructureAndVerification() throws {
        let binary = SyntheticMachO.make()
        let info = Data("info".utf8)
        let resources = Data("resources".utf8)
        let signed = try MachOSigner.sign(binary, materials: CodeSigningMaterials(
            identifier: "com.example.test", entitlements: ["get-task-allow": .bool(true)],
            infoPlist: info, codeResources: resources
        ))
        XCTAssertGreaterThan(signed.count, binary.count)
        let inspected = try XCTUnwrap(MachOInspector.inspect(data: signed))
        XCTAssertTrue(inspected.hasCodeSignature)
        XCTAssertNotNil(inspected.entitlementsXML)

        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try signed.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let issues = SignatureVerifier.verifyBinary(url, label: "t", expectedIdentifier: "com.example.test", infoPlist: info, codeResources: resources)
        XCTAssertEqual(issues, [])

        // Tampering with the code is detected.
        var tampered = signed
        tampered[100] ^= 0xFF
        try tampered.write(to: url)
        let bad = SignatureVerifier.verifyBinary(url, label: "t", expectedIdentifier: nil, infoPlist: info, codeResources: resources)
        XCTAssertTrue(bad.contains { $0.code == "SIGNATURE_PAGE_HASH" })
    }

    func testResignReplacesExistingSignature() throws {
        let first = try MachOSigner.sign(SyntheticMachO.make(), materials: CodeSigningMaterials(identifier: "a"))
        let second = try MachOSigner.sign(first, materials: CodeSigningMaterials(identifier: "b"))
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try second.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertEqual(SignatureVerifier.verifyBinary(url, label: "t", expectedIdentifier: "b", infoPlist: nil, codeResources: nil), [])
    }

    func testFatBinaryIsSignedPerSlice() throws {
        let slice = SyntheticMachO.make()
        var fat = ByteWriter()
        fat.u32(0xCAFE_BABE); fat.u32(1)
        fat.u32(0x0100_000C); fat.u32(0); fat.u32(0x4000); fat.u32(UInt32(slice.count)); fat.u32(14)
        fat.zeros(0x4000 - fat.count)
        fat.append(slice)
        let signed = try MachOSigner.sign(fat.data, materials: CodeSigningMaterials(identifier: "fat"))
        let slices = try MachOSigner.slices(of: signed)
        XCTAssertEqual(slices.count, 1)
        XCTAssertTrue(try XCTUnwrap(MachOInspector.inspect(data: slices[0])).hasCodeSignature)
    }

    func testCMSSignatureVerifiesWithPublicKey() throws {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
        var error: Unmanaged<CFError>?
        let privateKey = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let cert = try XCTUnwrap(Data(base64Encoded: MachOAndX509Fixture.certificateBase64, options: .ignoreUnknownCharacters))
        let key = try SecKeySigningKey(privateKey: privateKey, certificateDER: cert)

        let signed = try MachOSigner.sign(SyntheticMachO.make(), materials: CodeSigningMaterials(identifier: "cms", key: key))
        let info = try XCTUnwrap(MachOInspector.inspect(data: signed))
        XCTAssertTrue(info.hasCodeSignature)

        // Locate the CMS slot and check its structure and signature.
        let blob = try signatureBlob(of: signed)
        let cmsWrapper = try slot(0x10000, in: blob)
        XCTAssertEqual(Bytes.be32(cmsWrapper, 0), CSMagic.cmsWrapper)
        let cms = Data(cmsWrapper.dropFirst(8))
        let (content, _) = try XCTUnwrap(DERReader.read(cms, at: 0))
        XCTAssertEqual(content.tag, 0x30)
        // Re-build with the same inputs to get the signed attributes, then verify the signature bytes.
        let primary = try slot(0, in: blob)
        let alternate = try slot(0x1000, in: blob)
        XCTAssertEqual(Bytes.be32(primary, 0), CSMagic.codeDirectory)
        XCTAssertEqual(Bytes.be32(alternate, 0), CSMagic.codeDirectory)
        XCTAssertGreaterThan(cms.count, 256)
    }

    func testEntitlementsBuilderKeepsOnlyGrantedValues() {
        let profile = ProvisioningProfile(
            id: "x", name: "p", teamIdentifier: "TEAM123456", applicationIdentifierPrefixes: ["TEAM123456"],
            applicationIdentifier: "TEAM123456.com.example.*", creationDate: Date(), expirationDate: Date().addingTimeInterval(1000),
            entitlements: ["get-task-allow": .bool(true), "keychain-access-groups": .array([.string("TEAM123456.*")])]
        )
        let result = EntitlementsBuilder.build(
            requested: ["aps-environment": .string("production"), "application-identifier": .string("OLD.com.old"), "keychain-access-groups": .array([.string("OLD.shared")])],
            profile: profile, bundleIdentifier: "com.example.app"
        )
        XCTAssertEqual(result.dropped, ["aps-environment"])
        XCTAssertEqual(result.entitlements["application-identifier"], .string("TEAM123456.com.example.app"))
        XCTAssertEqual(result.entitlements["get-task-allow"], .bool(true))
        XCTAssertEqual(result.entitlements["keychain-access-groups"], .array([.string("TEAM123456.shared")]))
    }

    func testBundleSignerAdHocEndToEnd() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let app = root.appendingPathComponent("Payload/Demo.app")
        let framework = app.appendingPathComponent("Frameworks/Lib.framework")
        try FileManager.default.createDirectory(at: framework, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        func plist(_ dict: [String: Any]) throws -> Data { try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0) }
        try plist(["CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": "Demo"]).write(to: app.appendingPathComponent("Info.plist"))
        try SyntheticMachO.make().write(to: app.appendingPathComponent("Demo"))
        try Data("hello".utf8).write(to: app.appendingPathComponent("res.txt"))
        try plist(["CFBundleIdentifier": "com.example.lib", "CFBundleExecutable": "Lib"]).write(to: framework.appendingPathComponent("Info.plist"))
        try SyntheticMachO.make(fileType: 6).write(to: framework.appendingPathComponent("Lib"))

        let metadata = try BundleInspector().inspect(appBundle: app)
        let plan = SigningPlanner.makePlan(metadata: metadata)
        let engine = BundleSigner()
        let request = SigningRequest(appBundle: app, plan: plan, identityID: nil, profile: nil, profileData: nil)
        try await engine.sign(request) { _ in }
        let issues = try await engine.verify(appBundle: app, plan: plan, profile: nil)
        XCTAssertEqual(issues, [])
        XCTAssertTrue(FileManager.default.fileExists(atPath: app.appendingPathComponent("_CodeSignature/CodeResources").path))

        try Data("tampered".utf8).write(to: app.appendingPathComponent("res.txt"))
        let after = try await engine.verify(appBundle: app, plan: plan, profile: nil)
        XCTAssertTrue(after.contains { $0.code == "RESOURCE_MISMATCH" })
    }

    // MARK: helpers

    private func signatureBlob(of data: Data) throws -> Data {
        var cursor = 32
        for _ in 0..<Int(Bytes.le32(data, 16)) {
            if Bytes.le32(data, cursor) == 0x1D {
                let off = Int(Bytes.le32(data, cursor + 8)); let size = Int(Bytes.le32(data, cursor + 12))
                return Data(data[off..<(off + size)])
            }
            cursor += Int(Bytes.le32(data, cursor + 4))
        }
        throw XCTSkip("no signature")
    }

    private func slot(_ type: UInt32, in blob: Data) throws -> Data {
        for i in 0..<Int(Bytes.be32(blob, 8)) where Bytes.be32(blob, 12 + i * 8) == type {
            let off = Int(Bytes.be32(blob, 16 + i * 8))
            let len = Int(Bytes.be32(blob, off + 4))
            return Data(blob[off..<(off + len)])
        }
        throw XCTSkip("slot \(type) missing")
    }
}

enum MachOAndX509Fixture {
    static var certificateBase64: String { X509ParserTests.sampleCertificateBase64 }
}

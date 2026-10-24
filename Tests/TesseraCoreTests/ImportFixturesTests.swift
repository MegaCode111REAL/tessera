import XCTest
@testable import TesseraCore

/// Runs the sample IPAs in `TestAssets/` (made by `scripts/make_test_ipas.py`) through the real
/// import pipeline: archive checks, extraction, bundle inspection and validation.
final class ImportFixturesTests: XCTestCase {
    private var root: URL!
    private var store: SecureAssetStore!
    private var service: IPAImportService!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("tessera-import-\(UUID().uuidString)")
        store = try SecureAssetStore(root: root)
        let repository = LibraryRepository(directory: root)
        service = IPAImportService(
            store: store,
            metadataService: MetadataService(store: store),
            repository: repository
        )
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func fixture(_ name: String) -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // TesseraCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repository root
            .appendingPathComponent("TestAssets/\(name)")
    }

    private func codes(_ artifact: AppArtifact) -> Set<String> { Set(artifact.issues.map(\.code)) }

    private func assertCleanFailure(_ name: String, file: StaticString = #filePath, line: UInt = #line,
                                    matches: (Error) -> Bool) async {
        do {
            _ = try await service.importArchive(from: fixture(name))
            XCTFail("\(name) should have been rejected", file: file, line: line)
        } catch {
            XCTAssertTrue(matches(error), "\(name) failed with an unexpected error: \(error)", file: file, line: line)
        }
        // A rejected import leaves nothing behind.
        let stored = (try? FileManager.default.contentsOfDirectory(atPath: store.libraryDirectory.path)) ?? []
        XCTAssertTrue(stored.isEmpty, "\(name) left files in the library: \(stored)", file: file, line: line)
        XCTAssertEqual(store.storageUsage().temporary, 0, "\(name) left temporary files", file: file, line: line)
    }

    func testValidSampleIsInspectedFully() async throws {
        let artifact = try await service.importArchive(from: fixture("valid-sample.ipa"))
        let metadata = artifact.metadata
        XCTAssertEqual(metadata.bundleIdentifier, "com.example.tesserasample")
        XCTAssertEqual(metadata.displayName, "TesseraSample")
        XCTAssertEqual(metadata.versionDescription, "1.0 (1)")
        XCTAssertEqual(metadata.minimumOSVersion, "17.0")
        XCTAssertEqual(metadata.architectures, ["arm64"])
        XCTAssertEqual(metadata.deviceFamilies, [1, 2])
        XCTAssertFalse(metadata.isEncrypted)
        XCTAssertFalse(metadata.hasCodeSignature)
        XCTAssertEqual(metadata.extensions.count, 1)
        XCTAssertEqual(metadata.frameworks.count, 1)
        XCTAssertNotNil(artifact.iconFileName)
        XCTAssertEqual(artifact.status, .imported)
        XCTAssertTrue(codes(artifact).contains("UNSIGNED"))
        XCTAssertTrue(artifact.issues.filter { $0.severity == .error }.isEmpty)
        XCTAssertEqual(store.storageUsage().temporary, 0)
    }

    func testEncryptedBinaryNeedsAttention() async throws {
        let artifact = try await service.importArchive(from: fixture("encrypted.ipa"))
        XCTAssertTrue(artifact.metadata.isEncrypted)
        XCTAssertEqual(artifact.status, .needsAttention)
        XCTAssertTrue(codes(artifact).contains("ENCRYPTED_BINARY"))
    }

    func testSimulatorBuildNeedsAttention() async throws {
        let artifact = try await service.importArchive(from: fixture("simulator.ipa"))
        XCTAssertEqual(artifact.status, .needsAttention)
        XCTAssertTrue(codes(artifact).contains("SIMULATOR_BUILD"))
    }

    func testNoPayloadIsRejected() async {
        await assertCleanFailure("no-payload.ipa") { ($0 as? InspectionError) == .missingPayload }
    }

    func testTraversalIsRejectedBeforeExtraction() async {
        await assertCleanFailure("traversal.ipa") {
            if case ArchiveError.unsafePath = $0 { return true }
            return false
        }
        // The entry's target must not exist anywhere under the store, or beside it.
        let beside = root.deletingLastPathComponent().appendingPathComponent("escaped.txt")
        XCTAssertFalse(FileManager.default.fileExists(atPath: beside.path))
        let found = FileManager.default.enumerator(atPath: root.path)?.contains { ($0 as? String)?.hasSuffix("escaped.txt") == true }
        XCTAssertNotEqual(found, true)
    }

    func testSymlinkIsRejected() async {
        await assertCleanFailure("symlink.ipa") {
            if case ArchiveError.symlinkNotAllowed = $0 { return true }
            return false
        }
    }

    func testTwoAppsAreRejected() async {
        await assertCleanFailure("two-apps.ipa") {
            if case InspectionError.multipleAppBundles = $0 { return true }
            return false
        }
    }

    func testNonZipReportsTheUsersFileName() async {
        await assertCleanFailure("not-a-zip.ipa") { ($0 as? ArchiveError) == .cannotOpen("not-a-zip.ipa") }
    }

    // MARK: - Fake signed builds

    func testSignedSampleShowsSignatureEntitlementsAndProfile() async throws {
        let artifact = try await service.importArchive(from: fixture("signed-sample.ipa"))
        let metadata = artifact.metadata
        XCTAssertTrue(metadata.hasCodeSignature)
        XCTAssertTrue(metadata.hasEmbeddedProfile)
        XCTAssertEqual(metadata.existingEntitlements["aps-environment"], .string("development"))
        XCTAssertEqual(metadata.existingEntitlements["get-task-allow"], .bool(true))
        XCTAssertEqual(metadata.existingEntitlements["application-identifier"], .string("TEAM123456.com.example.signedsample"))

        let profile = try XCTUnwrap(metadata.embeddedProfile)
        XCTAssertEqual(profile.name, "Tessera Sample Dev")
        XCTAssertEqual(profile.id, "AAAAAAAA-1111-2222-3333-444444444444")
        XCTAssertEqual(profile.kind, .development)
        XCTAssertEqual(profile.teamIdentifier, "TEAM123456")
        XCTAssertEqual(profile.bundleIdentifierPattern, "com.example.signedsample")
        XCTAssertEqual(profile.provisionedDevices?.count, 2)
        XCTAssertEqual(profile.developerCertificateSHA1s.count, 1)
        XCTAssertFalse(profile.isExpired())

        XCTAssertTrue(metadata.nestedBundles.allSatisfy(\.hasCodeSignature))
        XCTAssertEqual(artifact.status, .imported)
        XCTAssertTrue(artifact.issues.isEmpty, "unexpected findings: \(artifact.issues)")
    }

    /// The sample's profile covers only the app's own ID, so the extension is (correctly) the one blocker.
    func testSignedSampleValidatesAgainstItsOwnProfileAndCertificate() async throws {
        let artifact = try await service.importArchive(from: fixture("signed-sample.ipa"))
        let profile = try XCTUnwrap(artifact.metadata.embeddedProfile)
        let identity = Fixtures.identity(id: profile.developerCertificateSHA1s[0])
        let issues = ValidationService(now: { Fixtures.now })
            .validateForSigning(metadata: artifact.metadata, profile: profile, identity: identity)
        XCTAssertEqual(issues.filter { $0.severity == .error }.map(\.code), ["NESTED_BUNDLE_ID_MISMATCH"], "\(issues)")
    }

    /// The binary here is laid out like a linker's output (header padding, __LINKEDIT last) and was
    /// fake-signed by the same script CI runs on the real Tessera build, so this checks Tessera's
    /// Mach-O reader against that exact transformation.
    func testTesseraLikeBinaryWithAppendedSignatureReadsAsSigned() async throws {
        let artifact = try await service.importArchive(from: fixture("tessera-like-fake-signed.ipa"))
        let metadata = artifact.metadata
        XCTAssertEqual(metadata.bundleIdentifier, "dev.tessera.app")
        XCTAssertEqual(metadata.architectures, ["arm64"])
        XCTAssertTrue(metadata.hasCodeSignature, "the appended LC_CODE_SIGNATURE was not detected")
        XCTAssertEqual(metadata.existingEntitlements["application-identifier"], .string("TEAM123456.dev.tessera.app"))
        XCTAssertEqual(metadata.existingEntitlements["get-task-allow"], .bool(true))
        XCTAssertEqual(metadata.existingEntitlements.count, 4)
        let profile = try XCTUnwrap(metadata.embeddedProfile)
        XCTAssertEqual(profile.name, "Tessera Fake Dev (test only)")
        XCTAssertEqual(profile.bundleIdentifierPattern, "dev.tessera.app")
        XCTAssertEqual(artifact.status, .imported)
        XCTAssertTrue(artifact.issues.isEmpty, "unexpected findings: \(artifact.issues)")
    }

    func testExpiredProfileAndUnsignedExtensionAreWarningsNotErrors() async throws {
        let artifact = try await service.importArchive(from: fixture("signed-expired-profile.ipa"))
        XCTAssertEqual(artifact.status, .imported)
        XCTAssertTrue(codes(artifact).isSuperset(of: ["EMBEDDED_PROFILE_EXPIRED", "NESTED_UNSIGNED"]), "\(artifact.issues)")
        XCTAssertTrue(artifact.issues.filter { $0.severity == .error }.isEmpty)

        let profile = try XCTUnwrap(artifact.metadata.embeddedProfile)
        XCTAssertEqual(profile.kind, .adHoc)
        XCTAssertTrue(profile.isExpired())

        // Trying to sign with that profile is blocked.
        let blocked = ValidationService().validateForSigning(
            metadata: artifact.metadata, profile: profile, identity: Fixtures.identity(id: profile.developerCertificateSHA1s[0]))
        XCTAssertTrue(blocked.contains { $0.code == "PROFILE_EXPIRED" && $0.severity == .error })
    }
}

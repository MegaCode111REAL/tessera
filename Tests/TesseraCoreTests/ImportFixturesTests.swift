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
}

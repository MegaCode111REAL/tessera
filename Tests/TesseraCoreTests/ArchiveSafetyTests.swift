import XCTest
@testable import TesseraCore

final class ArchiveSafetyTests: XCTestCase {
    func testAcceptsNormalPaths() throws {
        XCTAssertEqual(try ArchiveSafety.validate(entryPath: "Payload/App.app/Info.plist"), "Payload/App.app/Info.plist")
        XCTAssertEqual(try ArchiveSafety.validate(entryPath: "Payload/./App.app/"), "Payload/App.app")
    }

    func testRejectsTraversalAndAbsolutePaths() {
        for path in ["../evil", "Payload/../../evil", "/etc/passwd", "a\\b", "C:/x", "", "a\0b", ".."] {
            XCTAssertThrowsError(try ArchiveSafety.validate(entryPath: path), "should reject \(path.debugDescription)")
        }
    }

    func testResolveStaysInsideRoot() throws {
        let root = URL(fileURLWithPath: "/tmp/tessera-root")
        let url = try ArchiveSafety.resolve("Payload/App.app/x", inside: root)
        XCTAssertTrue(url.path.hasPrefix("/tmp/tessera-root/"))
    }

    func testLimitsRejectTooManyEntries() {
        let entries = (0..<5).map { ArchiveEntryInfo(path: "f\($0)", kind: .file, uncompressedSize: 1, compressedSize: 1) }
        XCTAssertThrowsError(try ArchiveSafety.checkLimits(entries, limits: ExtractionLimits(maxEntryCount: 3)))
    }

    func testLimitsRejectOversizedEntryAndTotal() {
        let big = [ArchiveEntryInfo(path: "big", kind: .file, uncompressedSize: 100, compressedSize: 100)]
        XCTAssertThrowsError(try ArchiveSafety.checkLimits(big, limits: ExtractionLimits(maxSingleEntryBytes: 10)))
        XCTAssertThrowsError(try ArchiveSafety.checkLimits(big, limits: ExtractionLimits(maxTotalUncompressedBytes: 10)))
    }

    func testLimitsRejectDecompressionBomb() {
        let bomb = [ArchiveEntryInfo(path: "bomb", kind: .file, uncompressedSize: 50_000_000, compressedSize: 1_000)]
        XCTAssertThrowsError(try ArchiveSafety.checkLimits(bomb, limits: .default)) { error in
            XCTAssertEqual(error as? ArchiveError, .suspiciousCompressionRatio("bomb"))
        }
    }

    func testTipaIsNotYetSupported() {
        XCTAssertThrowsError(try FormatAdapterRegistry.adapter(for: .tipa))
        XCTAssertTrue(ArchiveFormat.ipa.isSupported)
        XCTAssertFalse(ArchiveFormat.tipa.isSupported)
    }
}

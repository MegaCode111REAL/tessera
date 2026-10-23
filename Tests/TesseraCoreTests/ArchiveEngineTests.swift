import XCTest
import ZIPFoundation
@testable import TesseraCore

final class ArchiveEngineTests: XCTestCase {
    private var temp: URL!

    override func setUpWithError() throws {
        temp = FileManager.default.temporaryDirectory.appendingPathComponent("tessera-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: temp)
    }

    private func makeZip(_ files: [String: Data]) throws -> URL {
        let url = temp.appendingPathComponent("test.ipa")
        let archive = try Archive(url: url, accessMode: .create)
        for (path, data) in files.sorted(by: { $0.key < $1.key }) {
            try archive.addEntry(with: path, type: .file, uncompressedSize: Int64(data.count), provider: { position, size in
                data.subdata(in: Int(position)..<Int(position) + size)
            })
        }
        return url
    }

    func testInspectFindsAppBundle() throws {
        let url = try makeZip(["Payload/Foo.app/Info.plist": Data("x".utf8)])
        let result = try ArchiveEngine().inspect(archiveAt: url)
        XCTAssertTrue(result.hasPayload)
        XCTAssertEqual(result.appBundlePaths, ["Payload/Foo.app"])
    }

    func testInspectWithoutPayloadHasNoApps() throws {
        let url = try makeZip(["readme.txt": Data("x".utf8)])
        let result = try ArchiveEngine().inspect(archiveAt: url)
        XCTAssertFalse(result.hasPayload)
        XCTAssertTrue(result.appBundlePaths.isEmpty)
    }

    func testRejectsTraversalEntry() throws {
        let url = try makeZip(["Payload/../../evil.txt": Data("x".utf8)])
        XCTAssertThrowsError(try ArchiveEngine().inspect(archiveAt: url))
    }

    func testExtractRoundTrip() throws {
        let url = try makeZip(["Payload/Foo.app/Info.plist": Data("hello".utf8)])
        let out = temp.appendingPathComponent("out")
        try ArchiveEngine().extract(archiveAt: url, to: out)
        let data = try Data(contentsOf: out.appendingPathComponent("Payload/Foo.app/Info.plist"))
        XCTAssertEqual(String(data: data, encoding: .utf8), "hello")
    }

    func testReadEntryRespectsMaxBytes() throws {
        let url = try makeZip(["Payload/Foo.app/Info.plist": Data(repeating: 1, count: 100)])
        XCTAssertThrowsError(try ArchiveEngine().readEntry("Payload/Foo.app/Info.plist", from: url, maxBytes: 10))
        XCTAssertEqual(try ArchiveEngine().readEntry("Payload/Foo.app/Info.plist", from: url, maxBytes: 1000).count, 100)
    }

    func testNotAnArchiveFails() throws {
        let url = temp.appendingPathComponent("junk.ipa")
        try Data("not a zip".utf8).write(to: url)
        XCTAssertThrowsError(try ArchiveEngine().inspect(archiveAt: url))
    }
}

import XCTest
@testable import TesseraCore

final class SecureAssetStoreTests: XCTestCase {
    private var root: URL!
    private var store: SecureAssetStore!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("tessera-store-\(UUID().uuidString)")
        store = try SecureAssetStore(root: root)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func profile(id: String) -> ProvisioningProfile {
        var profile = Fixtures.profile()
        profile.id = id
        return profile
    }

    func testProfileRoundTripWithRealUUID() throws {
        let id = UUID().uuidString
        try store.saveProfile(data: Data("payload".utf8), profile: profile(id: id))
        XCTAssertEqual(try store.profileData(id: id), Data("payload".utf8))
        store.deleteProfile(id: id)
        XCTAssertThrowsError(try store.profileData(id: id))
    }

    func testTraversalIdentifiersNeverTouchTheFilesystem() throws {
        let victim = store.exportsDirectory.appendingPathComponent("victim.mobileprovision")
        try Data("keep".utf8).write(to: victim)

        for bad in ["../Exports/victim", "../../etc/passwd", "a/b", "", ".."] {
            XCTAssertThrowsError(try store.saveProfile(data: Data("x".utf8), profile: profile(id: bad)), bad)
            XCTAssertThrowsError(try store.profileData(id: bad), bad)
            store.deleteProfile(id: bad)
        }
        XCTAssertEqual(try Data(contentsOf: victim), Data("keep".utf8))
        let stray = (try? FileManager.default.contentsOfDirectory(atPath: store.exportsDirectory.path)) ?? []
        XCTAssertEqual(stray, ["victim.mobileprovision"])
    }
}

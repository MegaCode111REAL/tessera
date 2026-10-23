import XCTest
@testable import TesseraCore

enum Fixtures {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func profile(
        appID: String = "TEAM123456.com.example.app",
        expires: Date = now.addingTimeInterval(86_400),
        devices: [String]? = ["UDID1"],
        allDevices: Bool = false,
        getTaskAllow: Bool = false,
        certs: [String] = ["AAAA"],
        extra: [String: PlistValue] = [:]
    ) -> ProvisioningProfile {
        var entitlements: [String: PlistValue] = [
            "application-identifier": .string(appID),
            "get-task-allow": .bool(getTaskAllow),
        ]
        entitlements.merge(extra) { $1 }
        return ProvisioningProfile(
            id: "P1", name: "Test", teamIdentifier: "TEAM123456", teamName: "Team",
            applicationIdentifierPrefixes: ["TEAM123456"], applicationIdentifier: appID,
            creationDate: now.addingTimeInterval(-86_400), expirationDate: expires,
            platforms: ["iOS"], provisionedDevices: devices, provisionsAllDevices: allDevices,
            entitlements: entitlements, developerCertificateSHA1s: certs
        )
    }

    static func identity(id: String = "AAAA", expired: Bool = false, key: Bool = true) -> SigningIdentityInfo {
        SigningIdentityInfo(
            id: id, commonName: "iPhone Developer: Test", teamIdentifier: "TEAM123456",
            notBefore: now.addingTimeInterval(-1_000_000),
            notAfter: expired ? now.addingTimeInterval(-10) : now.addingTimeInterval(1_000_000),
            hasPrivateKey: key
        )
    }

    static func metadata(
        bundleID: String = "com.example.app",
        encrypted: Bool = false,
        entitlements: [String: PlistValue] = [:],
        nested: [NestedBundle] = []
    ) -> AppMetadata {
        AppMetadata(
            bundleIdentifier: bundleID, displayName: "App", shortVersion: "1.0", buildVersion: "1",
            executableName: "App", architectures: ["arm64"], isEncrypted: encrypted,
            hasCodeSignature: true, appFolderName: "App.app", nestedBundles: nested,
            existingEntitlements: entitlements
        )
    }

    static func profilePlist(uuid: String = "UUID-1", name: String = "Sample", expires: Date? = nil) -> Data {
        let dict: [String: Any] = [
            "UUID": uuid, "Name": name, "TeamName": "Team", "TeamIdentifier": ["TEAM123456"],
            "ApplicationIdentifierPrefix": ["TEAM123456"],
            "CreationDate": now.addingTimeInterval(-100),
            "ExpirationDate": expires ?? now.addingTimeInterval(100_000),
            "Platform": ["iOS"],
            "ProvisionedDevices": ["UDID1", "UDID2"],
            "DeveloperCertificates": [Data([1, 2, 3])],
            "Entitlements": ["application-identifier": "TEAM123456.com.example.*", "get-task-allow": false],
        ]
        let xml = try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        // Wrap in junk bytes to mimic the CMS envelope.
        return Data([0x30, 0x82, 0x01, 0x00]) + xml + Data([0x00, 0x01])
    }
}

final class ProfileParserTests: XCTestCase {
    func testParsesProfileInsideEnvelope() throws {
        let profile = try ProfileParser().parse(Fixtures.profilePlist())
        XCTAssertEqual(profile.id, "UUID-1")
        XCTAssertEqual(profile.teamIdentifier, "TEAM123456")
        XCTAssertEqual(profile.bundleIdentifierPattern, "com.example.*")
        XCTAssertEqual(profile.provisionedDevices?.count, 2)
        XCTAssertEqual(profile.kind, .adHoc)
        XCTAssertEqual(profile.developerCertificateSHA1s, [Fingerprint.sha1Hex(Data([1, 2, 3]))])
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try ProfileParser().parse(Data("hello".utf8))) { error in
            XCTAssertEqual(error as? ProfileParserError, .notAProfile)
        }
    }

    func testBundleIdentifierMatching() {
        let wildcard = Fixtures.profile(appID: "TEAM123456.com.example.*")
        XCTAssertTrue(wildcard.allowsBundleIdentifier("com.example.anything"))
        XCTAssertFalse(wildcard.allowsBundleIdentifier("com.other.app"))
        XCTAssertTrue(Fixtures.profile(appID: "TEAM123456.*").allowsBundleIdentifier("any.thing"))
        let exact = Fixtures.profile()
        XCTAssertTrue(exact.allowsBundleIdentifier("com.example.app"))
        XCTAssertFalse(exact.allowsBundleIdentifier("com.example.app2"))
    }

    func testKindDetection() {
        XCTAssertEqual(Fixtures.profile(devices: ["A"], getTaskAllow: true).kind, .development)
        XCTAssertEqual(Fixtures.profile(devices: ["A"]).kind, .adHoc)
        XCTAssertEqual(Fixtures.profile(devices: nil, allDevices: true).kind, .enterprise)
        XCTAssertEqual(Fixtures.profile(devices: nil).kind, .appStore)
    }
}

final class ValidationServiceTests: XCTestCase {
    private let service = ValidationService(now: { Fixtures.now })

    private func codes(_ issues: [ValidationIssue]) -> Set<String> { Set(issues.map(\.code)) }

    func testCleanSigningHasNoErrors() {
        let issues = service.validateForSigning(
            metadata: Fixtures.metadata(), profile: Fixtures.profile(), identity: Fixtures.identity()
        )
        XCTAssertTrue(issues.filter { $0.severity == .error }.isEmpty, "\(issues)")
    }

    func testExpiredProfileAndCertificate() {
        let issues = service.validateForSigning(
            metadata: Fixtures.metadata(),
            profile: Fixtures.profile(expires: Fixtures.now.addingTimeInterval(-5)),
            identity: Fixtures.identity(expired: true)
        )
        XCTAssertTrue(codes(issues).isSuperset(of: ["PROFILE_EXPIRED", "CERTIFICATE_EXPIRED"]))
    }

    func testBundleIDMismatch() {
        let issues = service.validateForSigning(
            metadata: Fixtures.metadata(bundleID: "com.other.app"),
            profile: Fixtures.profile(), identity: Fixtures.identity()
        )
        XCTAssertTrue(codes(issues).contains("BUNDLE_ID_MISMATCH"))
    }

    func testBundleIDOverrideFixesMismatch() {
        let issues = service.validateForSigning(
            metadata: Fixtures.metadata(bundleID: "com.other.app"),
            profile: Fixtures.profile(), identity: Fixtures.identity(),
            targetBundleIdentifier: "com.example.app"
        )
        XCTAssertFalse(codes(issues).contains("BUNDLE_ID_MISMATCH"))
    }

    func testCertificateNotInProfileAndMissingKey() {
        let issues = service.validateForSigning(
            metadata: Fixtures.metadata(), profile: Fixtures.profile(certs: ["BBBB"]),
            identity: Fixtures.identity(key: false)
        )
        XCTAssertTrue(codes(issues).isSuperset(of: ["CERTIFICATE_NOT_IN_PROFILE", "NO_PRIVATE_KEY"]))
    }

    func testMissingSelections() {
        let issues = service.validateForSigning(metadata: Fixtures.metadata(), profile: nil, identity: nil)
        XCTAssertTrue(codes(issues).isSuperset(of: ["MISSING_PROFILE", "MISSING_IDENTITY"]))
    }

    func testEntitlementNotInProfile() {
        let issues = service.validateForSigning(
            metadata: Fixtures.metadata(entitlements: ["com.apple.developer.healthkit": .bool(true)]),
            profile: Fixtures.profile(), identity: Fixtures.identity()
        )
        XCTAssertTrue(codes(issues).contains("ENTITLEMENT_NOT_IN_PROFILE"))
    }

    func testExtensionNeedsCoveredBundleID() {
        let ext = NestedBundle(relativePath: "PlugIns/Share.appex", kind: .appExtension, bundleIdentifier: "com.example.app.share")
        let exactProfile = Fixtures.profile()
        let issues = service.validateForSigning(
            metadata: Fixtures.metadata(nested: [ext]), profile: exactProfile, identity: Fixtures.identity()
        )
        XCTAssertTrue(codes(issues).contains("NESTED_BUNDLE_ID_MISMATCH"))

        let wildcard = Fixtures.profile(appID: "TEAM123456.com.example.*")
        let ok = service.validateForSigning(
            metadata: Fixtures.metadata(nested: [ext]), profile: wildcard, identity: Fixtures.identity()
        )
        XCTAssertFalse(codes(ok).contains("NESTED_BUNDLE_ID_MISMATCH"))
    }

    func testDeviceEligibility() {
        let profile = Fixtures.profile(devices: ["UDID1"])
        XCTAssertTrue(codes(service.validateForSigning(
            metadata: Fixtures.metadata(), profile: profile, identity: Fixtures.identity(), deviceIdentifier: "OTHER"
        )).contains("DEVICE_NOT_REGISTERED"))
        XCTAssertFalse(codes(service.validateForSigning(
            metadata: Fixtures.metadata(), profile: profile, identity: Fixtures.identity(), deviceIdentifier: "udid1"
        )).contains("DEVICE_NOT_REGISTERED"))
    }

    func testEncryptedBinaryIsBlocked() {
        let issues = service.inspectionIssues(for: Fixtures.metadata(encrypted: true))
        XCTAssertTrue(issues.contains { $0.code == "ENCRYPTED_BINARY" && $0.severity == .error })
    }
}

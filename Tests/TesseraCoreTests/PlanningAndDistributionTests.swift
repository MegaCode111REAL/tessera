import XCTest
@testable import TesseraCore

final class SigningPlannerTests: XCTestCase {
    func testNestedCodeIsSignedBeforeMainApp() {
        let nested = [
            NestedBundle(relativePath: "PlugIns/Share.appex", kind: .appExtension, bundleIdentifier: "com.example.app.share"),
            NestedBundle(relativePath: "Frameworks/Core.framework", kind: .framework),
            NestedBundle(relativePath: "Frameworks/libfoo.dylib", kind: .dynamicLibrary),
            NestedBundle(relativePath: "PlugIns/Share.appex/Frameworks/Inner.framework", kind: .framework),
        ]
        let plan = SigningPlanner.makePlan(metadata: Fixtures.metadata(nested: nested))
        XCTAssertTrue(plan.steps.last?.isMainApp == true)
        let paths = plan.steps.map(\.relativePath)
        // Deeper components come before the bundles that contain them.
        XCTAssertLessThan(paths.firstIndex(of: "PlugIns/Share.appex/Frameworks/Inner.framework")!,
                          paths.firstIndex(of: "PlugIns/Share.appex")!)
        // Libraries and frameworks are signed before extensions at the same depth.
        XCTAssertLessThan(paths.firstIndex(of: "Frameworks/Core.framework")!,
                          paths.firstIndex(of: "PlugIns/Share.appex")!)
    }

    func testExtensionIdentifiersFollowRename() {
        let ext = NestedBundle(relativePath: "PlugIns/Share.appex", kind: .appExtension, bundleIdentifier: "com.example.app.share")
        let plan = SigningPlanner.makePlan(metadata: Fixtures.metadata(nested: [ext]), targetBundleIdentifier: "com.new.name")
        XCTAssertEqual(plan.steps.first?.bundleIdentifier, "com.new.name.share")
        XCTAssertEqual(plan.targetBundleIdentifier, "com.new.name")
    }
}

final class DistributionTests: XCTestCase {
    private let service = DistributionService(now: { Fixtures.now })

    private func option(_ result: DistributionResult, _ mechanism: DistributionOption.Mechanism) -> DistributionOption {
        result.options.first { $0.mechanism == mechanism }!
    }

    func testNoProfileMeansNothingBeyondExport() {
        let result = service.evaluate(profile: nil, hasVerifiedSignedOutput: false)
        XCTAssertEqual(option(result, .registeredDevices).applicability, .notApplicable)
        XCTAssertEqual(option(result, .overTheAir).applicability, .notApplicable)
        XCTAssertEqual(option(result, .manualExport).applicability, .applicable)
    }

    func testRegisteredDevicesNeedsVerifiedSignedBuild() {
        let unsigned = service.evaluate(profile: Fixtures.profile(), hasVerifiedSignedOutput: false)
        XCTAssertEqual(option(unsigned, .registeredDevices).applicability, .conditional)
        XCTAssertFalse(option(unsigned, .registeredDevices).blockers.isEmpty)

        let signed = service.evaluate(profile: Fixtures.profile(), hasVerifiedSignedOutput: true)
        XCTAssertEqual(option(signed, .registeredDevices).applicability, .applicable)
    }

    func testOverTheAirIsNeverUnconditional() {
        let result = service.evaluate(profile: Fixtures.profile(), hasVerifiedSignedOutput: true)
        XCTAssertEqual(option(result, .overTheAir).applicability, .conditional)
    }

    func testNotarizationIsNeverFabricated() {
        let adHoc = service.evaluate(profile: Fixtures.profile(), hasVerifiedSignedOutput: true)
        if case .notApplicable = adHoc.notarization {} else { XCTFail("expected notApplicable") }

        let appStore = service.evaluate(profile: Fixtures.profile(devices: nil), hasVerifiedSignedOutput: true)
        XCTAssertEqual(appStore.notarization, .notSubmitted)
    }
}

final class ManifestTests: XCTestCase {
    func testRequiresHTTPS() {
        XCTAssertThrowsError(try ManifestBuilder.makeManifest(
            ipaURL: URL(string: "http://example.com/a.ipa")!, bundleIdentifier: "x", bundleVersion: "1", title: "t"))
        XCTAssertThrowsError(try ManifestBuilder.installURL(manifestURL: URL(string: "http://example.com/m.plist")!))
    }

    func testManifestContents() throws {
        let data = try ManifestBuilder.makeManifest(
            ipaURL: URL(string: "https://example.com/a.ipa")!, bundleIdentifier: "com.example.app", bundleVersion: "7", title: "App")
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        let item = (plist?["items"] as? [[String: Any]])?.first
        let assets = item?["assets"] as? [[String: Any]]
        XCTAssertEqual(assets?.first?["url"] as? String, "https://example.com/a.ipa")
        XCTAssertEqual((item?["metadata"] as? [String: Any])?["bundle-identifier"] as? String, "com.example.app")
    }

    func testInstallURLShape() throws {
        let url = try ManifestBuilder.installURL(manifestURL: URL(string: "https://example.com/m.plist")!)
        XCTAssertEqual(url.scheme, "itms-services")
        XCTAssertTrue(url.absoluteString.contains("action=download-manifest"))
    }
}

final class InstallationServiceTests: XCTestCase {
    func testAlternativeDistributionIsNeverAutomated() {
        let option = DistributionOption(mechanism: .alternativeDistribution, title: "Alt", applicability: .conditional, summary: "")
        let handoff = InstallationService().prepare(option: option, fileURL: nil, manifestURL: nil, hasVerifiedSignedOutput: true)
        if case .unavailable = handoff {} else { XCTFail("expected unavailable") }
    }

    func testOverTheAirNeedsVerifiedBuildAndHTTPSManifest() {
        let option = DistributionOption(mechanism: .overTheAir, title: "OTA", applicability: .conditional, summary: "")
        let service = InstallationService()
        let manifest = URL(string: "https://example.com/m.plist")
        if case .unavailable = service.prepare(option: option, fileURL: nil, manifestURL: manifest, hasVerifiedSignedOutput: false) {} else { XCTFail() }
        if case .unavailable = service.prepare(option: option, fileURL: nil, manifestURL: URL(string: "http://x/m.plist"), hasVerifiedSignedOutput: true) {} else { XCTFail() }
        if case .overTheAir = service.prepare(option: option, fileURL: nil, manifestURL: manifest, hasVerifiedSignedOutput: true) {} else { XCTFail() }
    }

    func testSigningEngineIsHonestlyUnavailable() async {
        let engine = UnavailableSigningEngine()
        XCTAssertFalse(engine.capability.isAvailable)
        let plan = SigningPlanner.makePlan(metadata: Fixtures.metadata())
        do {
            _ = try await engine.verify(appBundle: URL(fileURLWithPath: "/tmp"), plan: plan, profile: Fixtures.profile())
            XCTFail("should throw")
        } catch {
            XCTAssertTrue(error is SigningError)
        }
    }
}

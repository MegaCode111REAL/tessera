import XCTest
@testable import TesseraCore

final class IncomingLinkParserTests: XCTestCase {
    private func parse(_ string: String) -> IncomingAction {
        IncomingLinkParser.parse(URL(string: string)!)
    }

    private func isInvalid(_ action: IncomingAction) -> Bool {
        if case .invalid = action { return true }
        return false
    }

    func testInstallLinkWithEncodedURL() {
        let action = parse("tessera://install?url=https%3A%2F%2Fexample.com%2Fapps%2Ffoo.ipa")
        XCTAssertEqual(action, .download(URL(string: "https://example.com/apps/foo.ipa")!))
    }

    func testImportHostAndIpaParameterAreAccepted() {
        XCTAssertEqual(parse("tessera://import?url=https://example.com/a.ipa"), .download(URL(string: "https://example.com/a.ipa")!))
        XCTAssertEqual(parse("tessera://install?ipa=https://example.com/a.ipa"), .download(URL(string: "https://example.com/a.ipa")!))
        XCTAssertEqual(parse("TESSERA://INSTALL?URL=https://example.com/a.ipa"), .download(URL(string: "https://example.com/a.ipa")!))
    }

    func testRejectsNonHTTPSDownloads() {
        XCTAssertTrue(isInvalid(parse("tessera://install?url=http://example.com/a.ipa")))
        XCTAssertTrue(isInvalid(parse("tessera://install?url=ftp://example.com/a.ipa")))
        XCTAssertTrue(isInvalid(parse("tessera://install?url=file:///etc/passwd")))
        XCTAssertTrue(isInvalid(parse("tessera://install?url=javascript:alert(1)")))
    }

    func testRejectsMissingOrUnknown() {
        XCTAssertTrue(isInvalid(parse("tessera://install")))
        XCTAssertTrue(isInvalid(parse("tessera://install?url=")))
        XCTAssertTrue(isInvalid(parse("tessera://delete?url=https://example.com/a.ipa")))
        XCTAssertTrue(isInvalid(parse("otherapp://install?url=https://example.com/a.ipa")))
        XCTAssertTrue(isInvalid(parse("https://example.com/a.ipa")))
    }

    func testRejectsCredentialsAndOverlongURLs() {
        XCTAssertTrue(isInvalid(parse("tessera://install?url=https://user:pass@example.com/a.ipa")))
        let long = "https://example.com/" + String(repeating: "a", count: 3000) + ".ipa"
        XCTAssertTrue(isInvalid(IncomingLinkParser.validateDownload(long)))
    }

    func testFileURLs() {
        let ipa = URL(fileURLWithPath: "/tmp/Inbox/App.ipa")
        XCTAssertEqual(IncomingLinkParser.parse(ipa), .importFile(ipa))
        XCTAssertEqual(IncomingLinkParser.parse(URL(fileURLWithPath: "/tmp/App.IPA")), .importFile(URL(fileURLWithPath: "/tmp/App.IPA")))
        XCTAssertTrue(isInvalid(IncomingLinkParser.parse(URL(fileURLWithPath: "/tmp/notes.txt"))))
    }

    func testMakeInstallLinkRoundTrips() throws {
        let target = URL(string: "https://example.com/dir/my app.ipa?token=a&b=c")!
        let link = try XCTUnwrap(IncomingLinkParser.makeInstallLink(for: target))
        XCTAssertEqual(IncomingLinkParser.parse(link), .download(target))
    }
}

final class DownloadServiceTests: XCTestCase {
    func testFileNameIsSafe() {
        XCTAssertEqual(DownloadService.fileName(for: URL(string: "https://example.com/a/My%20App.ipa")!), "My App.ipa")
        XCTAssertEqual(DownloadService.fileName(for: URL(string: "https://example.com/download?id=1")!), "download.ipa")
        XCTAssertEqual(DownloadService.fileName(for: URL(string: "https://example.com/x.zip")!), "download.ipa")
        XCTAssertEqual(DownloadService.fileName(for: URL(string: "https://example.com/.ipa")!), "download.ipa")
    }

    func testRefusesPlainHTTPWithoutTouchingTheNetwork() async {
        do {
            _ = try await DownloadService().download(URL(string: "http://example.com/a.ipa")!, into: FileManager.default.temporaryDirectory)
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(error as? DownloadError, .httpsRequired)
        }
    }
}

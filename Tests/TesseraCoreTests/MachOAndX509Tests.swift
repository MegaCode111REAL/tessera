import XCTest
@testable import TesseraCore

final class MachOInspectorTests: XCTestCase {
    private func le32(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 24) & 0xFF)] }
    private func be32(_ v: UInt32) -> [UInt8] { le32(v).reversed() }

    /// Builds a minimal 64-bit arm64 Mach-O with the given load commands.
    private func macho(commands: [[UInt8]]) -> Data {
        let body = commands.flatMap { $0 }
        var bytes: [UInt8] = []
        bytes += [0xCF, 0xFA, 0xED, 0xFE]
        bytes += le32(0x0100_000C)            // CPU_TYPE_ARM64
        bytes += le32(0)                      // subtype
        bytes += le32(2)                      // filetype
        bytes += le32(UInt32(commands.count))
        bytes += le32(UInt32(body.count))
        bytes += le32(0) + le32(0)            // flags + reserved
        bytes += body
        return Data(bytes)
    }

    func testThinArm64() throws {
        let info = try XCTUnwrap(MachOInspector.inspect(data: macho(commands: [])))
        // No commands: parser should still report the architecture.
        XCTAssertEqual(info.architectures, ["arm64"])
    }

    func testDetectsEncryption() throws {
        func encryption(cryptid: UInt32) -> [UInt8] {
            le32(0x2C) + le32(24) + le32(0x4000) + le32(0x1000) + le32(cryptid) + le32(0)
        }
        XCTAssertTrue(try XCTUnwrap(MachOInspector.inspect(data: macho(commands: [encryption(cryptid: 1)]))).isEncrypted)
        XCTAssertFalse(try XCTUnwrap(MachOInspector.inspect(data: macho(commands: [encryption(cryptid: 0)]))).isEncrypted)
    }

    func testExtractsEntitlementsFromSignature() throws {
        let xml = Data("<plist/>".utf8)
        // SuperBlob: magic, length, count, [type, offset], then the entitlements blob.
        let blobStart = 12 + 8
        var blob = Data(be32(0xFADE_0CC0) + be32(UInt32(blobStart + 8 + xml.count)) + be32(1) + be32(5) + be32(UInt32(blobStart)))
        blob += Data(be32(0xFADE_7171) + be32(UInt32(8 + xml.count))) + xml

        let headerSize = 32
        let commandSize = 16
        let signatureOffset = headerSize + commandSize
        let command = le32(0x1D) + le32(UInt32(commandSize)) + le32(UInt32(signatureOffset)) + le32(UInt32(blob.count))
        let data = macho(commands: [command]) + blob

        let info = try XCTUnwrap(MachOInspector.inspect(data: data))
        XCTAssertTrue(info.hasCodeSignature)
        XCTAssertEqual(info.entitlementsXML, xml)
    }

    func testRejectsNonMachO() {
        XCTAssertNil(MachOInspector.inspect(data: Data("hello world".utf8)))
        XCTAssertNil(MachOInspector.inspect(data: Data()))
    }

    func testTruncatedDataDoesNotCrash() {
        let full = macho(commands: [le32(0x1D) + le32(16) + le32(9999) + le32(9999)])
        for length in 0..<full.count {
            _ = MachOInspector.inspect(data: full.prefix(length))
        }
    }
}

final class X509ParserTests: XCTestCase {
    func testParsesGeneratedCertificate() throws {
        // A real self-signed certificate (generated with openssl) embedded as base64 DER.
        let der = try XCTUnwrap(Data(base64Encoded: Self.sampleCertificateBase64, options: .ignoreUnknownCharacters))
        let summary = try XCTUnwrap(X509Parser.parse(der: der))
        XCTAssertEqual(summary.commonName, "Tessera Test")
        XCTAssertEqual(summary.organization, "Tessera Org")
        XCTAssertEqual(summary.organizationalUnit, "TEAM123456")
        XCTAssertLessThan(summary.notBefore, summary.notAfter)

        let identity = try XCTUnwrap(CertificateManager.summarize(certificateDER: der, hasPrivateKey: true))
        XCTAssertEqual(identity.teamIdentifier, "TEAM123456")
        XCTAssertEqual(identity.id.count, 40)
    }

    func testGarbageIsRejected() {
        XCTAssertNil(X509Parser.parse(der: Data([0x30, 0x03, 0x01, 0x01, 0xFF])))
        XCTAssertNil(X509Parser.parse(der: Data()))
    }

    static let sampleCertificateBase64 = "MIIDfzCCAmegAwIBAgIUCuhbUuHOXnRXrvkfR9gTEWZ8tfswDQYJKoZIhvcNAQELBQAwTzEVMBMGA1UEAwwMVGVzc2VyYSBUZXN0MRQwEgYDVQQKDAtUZXNzZXJhIE9yZzETMBEGA1UECwwKVEVBTTEyMzQ1NjELMAkGA1UEBhMCVVMwHhcNMjYxMDIzMDYyMTA3WhcNMzYxMDIwMDYyMTA3WjBPMRUwEwYDVQQDDAxUZXNzZXJhIFRlc3QxFDASBgNVBAoMC1Rlc3NlcmEgT3JnMRMwEQYDVQQLDApURUFNMTIzNDU2MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ2n0aDIMouMl72eB7/4BK4Tcs661s3ddn7ffBgGmqbPzksJYOXaidZzjb5ox+5pWkxRPI1+FjGWyMOgpe0FYxHlD/STvCuqSyF0dUPef2sQLZzqHOi6+FHBprUP3re8/9Kht9DHk/XrNuladoVb5el9cFhGx5bcLQl1qjQqRt8HKVDGKg1ovYIhEc2T7qvDULg96NwQvhF1pNr167ll3DQyipQnfJLsEZv/BFIdb8fbpXX5P4VVI2Yi89pP8g27lA/18N8D1y+G7gETWm3OpB011ptOonBhzrn076IfXpq/2776Gc35VqGwuMkY22CPxKeO8Hrj7wS/Kyc9EK5I9C0CAwEAAaNTMFEwHQYDVR0OBBYEFMrvNQ9G6zddIG/W5fzmkv46lajJMB8GA1UdIwQYMBaAFMrvNQ9G6zddIG/W5fzmkv46lajJMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEoiYVfMnvzd0RA47INEBt3yJ1RT1KODF/YyvIfuVTN/kaWEyEA0ofbse/XSAh2yMxKgS6hlkgUkkvzuaVQQyNGML89xHHfADA+M+Zvx7DscbRQ0qaQq55sEJ6JARu0TBVeQK+Wd1IiniibEuz4jwjw0cAtSh1pUNV/sCbkRKEXVMdzONUJuKETUjchzX/EF+1F4pVhsGLsZExtUB5OzE4ngBu9aA/OQE/3eG5R/Fu8j5bx0GzAmfJDGLTzkd0o9eYXQ0yiDh/aCBr4yV0dmcAxAbWYLN/DjoijC+ZCmoPNuU77eRAVWaNuszSH3ySr2qKSVa1XyWM9hQ68+TU5Ro9Y="
}

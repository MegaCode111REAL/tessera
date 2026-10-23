import Foundation
import CryptoKit

enum Fingerprint {
    /// Uppercase hexadecimal SHA-1, the fingerprint format used by provisioning profiles.
    static func sha1Hex(_ data: Data) -> String {
        Insecure.SHA1.hash(data: data)
            .map { String(format: "%02X", $0) }
            .joined()
    }
}

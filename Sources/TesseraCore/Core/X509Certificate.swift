import Foundation

/// Minimal X.509 reader. iOS exposes no public API for a certificate's validity dates or
/// subject fields, so Tessera reads the few fields it needs directly from the DER encoding.
public struct X509Summary: Equatable, Sendable {
    public var commonName: String?
    public var organization: String?
    public var organizationalUnit: String?
    public var country: String?
    public var issuerCommonName: String?
    public var notBefore: Date
    public var notAfter: Date
}

public enum X509Parser {
    private struct Element {
        var tag: UInt8
        var content: Range<Int>
        var end: Int
    }

    private static func read(_ bytes: [UInt8], at position: Int) -> Element? {
        guard position >= 0, position + 2 <= bytes.count else { return nil }
        let tag = bytes[position]
        var index = position + 1
        var length = Int(bytes[index])
        index += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count >= 1, count <= 4, index + count <= bytes.count else { return nil }
            length = 0
            for offset in 0..<count {
                length = (length << 8) | Int(bytes[index + offset])
            }
            index += count
        }
        guard length >= 0, index + length <= bytes.count else { return nil }
        return Element(tag: tag, content: index..<(index + length), end: index + length)
    }

    /// Parses a DER-encoded certificate. Returns `nil` if the structure is not recognised.
    public static func parse(der: Data) -> X509Summary? {
        let bytes = [UInt8](der)
        guard let certificate = read(bytes, at: 0), certificate.tag == 0x30,
              let tbs = read(bytes, at: certificate.content.lowerBound), tbs.tag == 0x30 else {
            return nil
        }

        var position = tbs.content.lowerBound
        guard var element = read(bytes, at: position) else { return nil }
        if element.tag == 0xA0 {           // explicit version
            position = element.end
            guard let next = read(bytes, at: position) else { return nil }
            element = next
        }
        guard element.tag == 0x02 else { return nil }                       // serial number
        position = element.end
        guard let signatureAlgorithm = read(bytes, at: position), signatureAlgorithm.tag == 0x30 else { return nil }
        position = signatureAlgorithm.end
        guard let issuer = read(bytes, at: position), issuer.tag == 0x30 else { return nil }
        position = issuer.end
        guard let validity = read(bytes, at: position), validity.tag == 0x30 else { return nil }
        position = validity.end
        guard let subject = read(bytes, at: position), subject.tag == 0x30 else { return nil }

        guard let notBeforeElement = read(bytes, at: validity.content.lowerBound),
              let notAfterElement = read(bytes, at: notBeforeElement.end),
              let notBefore = parseTime(bytes, notBeforeElement),
              let notAfter = parseTime(bytes, notAfterElement) else {
            return nil
        }

        let subjectFields = parseName(bytes, subject)
        let issuerFields = parseName(bytes, issuer)

        return X509Summary(
            commonName: subjectFields["2.5.4.3"],
            organization: subjectFields["2.5.4.10"],
            organizationalUnit: subjectFields["2.5.4.11"],
            country: subjectFields["2.5.4.6"],
            issuerCommonName: issuerFields["2.5.4.3"],
            notBefore: notBefore,
            notAfter: notAfter
        )
    }

    private static func parseTime(_ bytes: [UInt8], _ element: Element) -> Date? {
        guard element.tag == 0x17 || element.tag == 0x18 else { return nil }
        guard let text = String(bytes: bytes[element.content], encoding: .ascii) else { return nil }
        let digits = text.hasSuffix("Z") ? String(text.dropLast()) : text
        let yearDigits = element.tag == 0x17 ? 2 : 4
        guard digits.count >= yearDigits + 8, digits.allSatisfy(\.isNumber) else { return nil }

        func number(_ start: Int, _ length: Int) -> Int? {
            let chars = Array(digits)
            guard start + length <= chars.count else { return nil }
            return Int(String(chars[start..<(start + length)]))
        }

        guard var year = number(0, yearDigits),
              let month = number(yearDigits, 2),
              let day = number(yearDigits + 2, 2),
              let hour = number(yearDigits + 4, 2),
              let minute = number(yearDigits + 6, 2) else {
            return nil
        }
        let second = number(yearDigits + 8, 2) ?? 0
        if element.tag == 0x17 { year += year >= 50 ? 1900 : 2000 }

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(from: DateComponents(
            year: year, month: month, day: day, hour: hour, minute: minute, second: second
        ))
    }

    /// Returns a map of dotted OID string to string value for a Name structure.
    private static func parseName(_ bytes: [UInt8], _ name: Element) -> [String: String] {
        var result: [String: String] = [:]
        var rdnPosition = name.content.lowerBound
        while rdnPosition < name.content.upperBound, let rdn = read(bytes, at: rdnPosition) {
            rdnPosition = rdn.end
            guard rdn.tag == 0x31 else { continue }
            var attributePosition = rdn.content.lowerBound
            while attributePosition < rdn.content.upperBound, let attribute = read(bytes, at: attributePosition) {
                attributePosition = attribute.end
                guard attribute.tag == 0x30,
                      let oid = read(bytes, at: attribute.content.lowerBound), oid.tag == 0x06,
                      let value = read(bytes, at: oid.end) else { continue }
                let key = oidString(bytes[oid.content])
                if result[key] == nil, let text = decodeString(bytes, value) {
                    result[key] = text
                }
            }
        }
        return result
    }

    private static func oidString(_ content: ArraySlice<UInt8>) -> String {
        guard let first = content.first else { return "" }
        var parts = [Int(first) / 40, Int(first) % 40]
        var accumulator = 0
        for byte in content.dropFirst() {
            accumulator = (accumulator << 7) | Int(byte & 0x7F)
            if byte & 0x80 == 0 {
                parts.append(accumulator)
                accumulator = 0
            }
        }
        return parts.map(String.init).joined(separator: ".")
    }

    private static func decodeString(_ bytes: [UInt8], _ element: Element) -> String? {
        let content = Data(bytes[element.content])
        switch element.tag {
        case 0x0C: return String(data: content, encoding: .utf8)         // UTF8String
        case 0x13, 0x16: return String(data: content, encoding: .ascii)   // PrintableString, IA5String
        case 0x14: return String(data: content, encoding: .isoLatin1)     // TeletexString
        case 0x1E: return String(data: content, encoding: .utf16BigEndian) // BMPString
        default: return nil
        }
    }
}

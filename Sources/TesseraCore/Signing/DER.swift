import Foundation

/// Minimal DER encoder (ASN.1), enough for CMS signatures and Apple's DER entitlements.
enum DER {
    static func length(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(length(content.count))
        out.append(content)
        return out
    }

    static func concat(_ items: [Data]) -> Data {
        var out = Data()
        for item in items { out.append(item) }
        return out
    }

    static func sequence(_ items: [Data]) -> Data { tlv(0x30, concat(items)) }

    /// A SET with its members in the order given (the caller sorts when DER requires it).
    static func set(_ items: [Data]) -> Data { tlv(0x31, concat(items)) }

    /// A SET OF with members sorted by encoding, as DER requires.
    static func setSorted(_ items: [Data]) -> Data {
        set(items.sorted { $0.lexicographicallyPrecedes($1) })
    }

    static func octetString(_ data: Data) -> Data { tlv(0x04, data) }
    static func null() -> Data { Data([0x05, 0x00]) }
    static func boolean(_ value: Bool) -> Data { tlv(0x01, Data([value ? 0xFF : 0x00])) }
    static func utf8(_ string: String) -> Data { tlv(0x0C, Data(string.utf8)) }

    /// Context-specific constructed tag `[number]` wrapping `content`.
    static func contextConstructed(_ number: UInt8, _ content: Data) -> Data { tlv(0xA0 | number, content) }

    /// Minimal two's-complement INTEGER.
    static func integer(_ value: Int) -> Data {
        var bytes: [UInt8] = []
        var v = value
        repeat {
            bytes.insert(UInt8(truncatingIfNeeded: v & 0xFF), at: 0)
            v >>= 8
        } while !((v == 0 && bytes[0] & 0x80 == 0) || (v == -1 && bytes[0] & 0x80 != 0))
        return tlv(0x02, Data(bytes))
    }

    static func oid(_ dotted: String) -> Data {
        let parts = dotted.split(separator: ".").compactMap { UInt64($0) }
        guard parts.count >= 2 else { return tlv(0x06, Data()) }

        func base128(_ value: UInt64) -> [UInt8] {
            var out: [UInt8] = [UInt8(value & 0x7F)]
            var rest = value >> 7
            while rest > 0 {
                out.insert(UInt8(rest & 0x7F) | 0x80, at: 0)
                rest >>= 7
            }
            return out
        }

        var body = base128(parts[0] * 40 + parts[1])
        for part in parts.dropFirst(2) { body += base128(part) }
        return tlv(0x06, Data(body))
    }

    /// UTCTime in `yyMMddHHmmssZ` form (valid for years 1950-2049).
    static func utcTime(_ date: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tlv(0x17, Data(formatter.string(from: date).utf8))
    }
}

/// One parsed DER element.
struct DERElement {
    var tag: UInt8
    /// The complete encoding (tag, length and content).
    var raw: Data
    var content: Data
}

enum DERReader {
    /// Reads one element at `position`; returns it and the position just after it.
    static func read(_ data: Data, at position: Int) -> (element: DERElement, next: Int)? {
        let bytes = [UInt8](data)
        guard position >= 0, position + 2 <= bytes.count else { return nil }
        let tag = bytes[position]
        var index = position + 1
        var length = Int(bytes[index])
        index += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count >= 1, count <= 4, index + count <= bytes.count else { return nil }
            length = 0
            for offset in 0..<count { length = (length << 8) | Int(bytes[index + offset]) }
            index += count
        }
        guard length >= 0, index + length <= bytes.count else { return nil }
        let element = DERElement(
            tag: tag,
            raw: Data(bytes[position..<(index + length)]),
            content: Data(bytes[index..<(index + length)])
        )
        return (element, index + length)
    }

    static func children(of element: DERElement) -> [DERElement]? {
        var out: [DERElement] = []
        var position = 0
        while position < element.content.count {
            guard let (child, next) = read(element.content, at: position) else { return nil }
            out.append(child)
            position = next
        }
        return out
    }

    /// `(issuer Name, serialNumber)` raw encodings from a certificate, for CMS `IssuerAndSerialNumber`.
    static func issuerAndSerial(ofCertificate der: Data) -> (issuer: Data, serial: Data)? {
        guard let (certificate, _) = read(der, at: 0), certificate.tag == 0x30,
              let top = children(of: certificate), let tbs = top.first, tbs.tag == 0x30,
              var fields = children(of: tbs) else { return nil }
        if let first = fields.first, first.tag == 0xA0 { fields.removeFirst() }
        guard fields.count >= 3, fields[0].tag == 0x02 else { return nil }
        return (issuer: fields[2].raw, serial: fields[0].raw)
    }
}

/// Apple's DER encoding of an entitlements dictionary (code-signature slot 7).
enum EntitlementsDER {
    enum EncodingError: Error, LocalizedError {
        case unsupportedValue(String)
        var errorDescription: String? {
            switch self {
            case .unsupportedValue(let key): return "The entitlement “\(key)” has a value type that cannot be encoded."
            }
        }
    }

    static func encode(_ entitlements: [String: PlistValue]) throws -> Data {
        // [APPLICATION 16] { SET { SEQUENCE { UTF8String key, value }, ... } }
        DER.tlv(0x70, try dictionary(entitlements))
    }

    private static func dictionary(_ dict: [String: PlistValue]) throws -> Data {
        var entries: [(key: Data, encoded: Data)] = []
        for key in dict.keys {
            let value = try encode(value: dict[key]!, key: key)
            let keyBytes = Data(key.utf8)
            entries.append((keyBytes, DER.sequence([DER.utf8(key), value])))
        }
        entries.sort { $0.key.lexicographicallyPrecedes($1.key) }
        return DER.set(entries.map(\.encoded))
    }

    private static func encode(value: PlistValue, key: String) throws -> Data {
        switch value {
        case .bool(let flag): return DER.boolean(flag)
        case .integer(let number): return DER.integer(number)
        case .string(let text): return DER.utf8(text)
        case .data(let bytes): return DER.octetString(bytes)
        case .array(let items): return DER.sequence(try items.map { try encode(value: $0, key: key) })
        case .dictionary(let dict): return try dictionary(dict)
        case .real, .date: throw EncodingError.unsupportedValue(key)
        }
    }
}

extension PlistValue {
    /// A Foundation object suitable for `PropertyListSerialization`.
    var foundationObject: Any {
        switch self {
        case .string(let value): return value
        case .integer(let value): return NSNumber(value: value)
        case .real(let value): return NSNumber(value: value)
        case .bool(let value): return NSNumber(value: value)
        case .date(let value): return value
        case .data(let value): return value
        case .array(let values): return values.map { $0.foundationObject }
        case .dictionary(let values): return values.mapValues { $0.foundationObject }
        }
    }
}

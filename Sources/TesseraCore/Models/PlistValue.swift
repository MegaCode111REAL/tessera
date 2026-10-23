import Foundation

/// A Codable, Hashable representation of a property-list value.
/// Used for entitlements and other plist-backed metadata so they can be
/// persisted, compared, and displayed without losing type information.
public enum PlistValue: Codable, Hashable, Sendable {
    case string(String)
    case integer(Int)
    case real(Double)
    case bool(Bool)
    case date(Date)
    case data(Data)
    case array([PlistValue])
    case dictionary([String: PlistValue])

    /// Converts a value produced by `PropertyListSerialization` into a `PlistValue`.
    public init(any value: Any) {
        if let date = value as? Date {
            self = .date(date)
        } else if let data = value as? Data {
            self = .data(data)
        } else if let string = value as? String {
            self = .string(string)
        } else if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                self = .bool(number.boolValue)
            } else if CFNumberIsFloatType(number) {
                self = .real(number.doubleValue)
            } else {
                self = .integer(number.intValue)
            }
        } else if let array = value as? [Any] {
            self = .array(array.map { PlistValue(any: $0) })
        } else if let dict = value as? [String: Any] {
            self = .dictionary(dict.mapValues { PlistValue(any: $0) })
        } else {
            self = .string(String(describing: value))
        }
    }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var arrayValue: [PlistValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    /// A compact, human-readable rendering suitable for list rows and reports.
    public var displayString: String {
        switch self {
        case .string(let value): return value
        case .integer(let value): return String(value)
        case .real(let value): return String(value)
        case .bool(let value): return value ? "true" : "false"
        case .date(let value): return ISO8601DateFormatter().string(from: value)
        case .data(let value): return "<\(value.count) bytes>"
        case .array(let values):
            return "[" + values.map(\.displayString).joined(separator: ", ") + "]"
        case .dictionary(let values):
            let body = values.keys.sorted().map { "\($0): \(values[$0]!.displayString)" }
            return "{" + body.joined(separator: ", ") + "}"
        }
    }
}

public extension Dictionary where Key == String, Value == Any {
    /// Converts a property-list dictionary into `[String: PlistValue]`.
    func toPlistValues() -> [String: PlistValue] {
        mapValues { PlistValue(any: $0) }
    }
}

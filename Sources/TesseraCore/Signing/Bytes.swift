import Foundation
import CryptoKit

/// Big-endian byte builder used for code-signature blobs (which are big-endian on disk).
struct ByteWriter {
    private(set) var data = Data()

    var count: Int { data.count }

    mutating func u8(_ value: UInt8) { data.append(value) }

    mutating func u32(_ value: UInt32) {
        data.append(UInt8(truncatingIfNeeded: value >> 24))
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func u64(_ value: UInt64) {
        u32(UInt32(truncatingIfNeeded: value >> 32))
        u32(UInt32(truncatingIfNeeded: value))
    }

    mutating func append(_ bytes: Data) { data.append(bytes) }

    mutating func zeros(_ count: Int) {
        if count > 0 { data.append(Data(count: count)) }
    }
}

/// Random-access helpers for zero-based `Data`.
enum Bytes {
    static func be32(_ data: Data, _ offset: Int) -> UInt32 {
        let b = data.startIndex + offset
        return UInt32(data[b]) << 24 | UInt32(data[b + 1]) << 16 | UInt32(data[b + 2]) << 8 | UInt32(data[b + 3])
    }

    static func be64(_ data: Data, _ offset: Int) -> UInt64 {
        (UInt64(be32(data, offset)) << 32) | UInt64(be32(data, offset + 4))
    }

    static func le32(_ data: Data, _ offset: Int) -> UInt32 {
        let b = data.startIndex + offset
        return UInt32(data[b]) | UInt32(data[b + 1]) << 8 | UInt32(data[b + 2]) << 16 | UInt32(data[b + 3]) << 24
    }

    static func le64(_ data: Data, _ offset: Int) -> UInt64 {
        UInt64(le32(data, offset)) | (UInt64(le32(data, offset + 4)) << 32)
    }

    static func putLE32(_ data: inout Data, _ offset: Int, _ value: UInt32) {
        let b = data.startIndex + offset
        data[b] = UInt8(truncatingIfNeeded: value)
        data[b + 1] = UInt8(truncatingIfNeeded: value >> 8)
        data[b + 2] = UInt8(truncatingIfNeeded: value >> 16)
        data[b + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }

    static func putLE64(_ data: inout Data, _ offset: Int, _ value: UInt64) {
        putLE32(&data, offset, UInt32(truncatingIfNeeded: value))
        putLE32(&data, offset + 4, UInt32(truncatingIfNeeded: value >> 32))
    }

    static func alignUp(_ value: Int, _ alignment: Int) -> Int {
        (value + alignment - 1) / alignment * alignment
    }

    /// A NUL-terminated or NUL-padded string field.
    static func cString(_ data: Data, _ offset: Int, maxLength: Int) -> String {
        let start = data.startIndex + offset
        let slice = data[start..<(start + maxLength)]
        let trimmed = slice.prefix { $0 != 0 }
        return String(decoding: trimmed, as: UTF8.self)
    }
}

enum HashKind: Sendable {
    case sha1
    case sha256

    /// The `hashType` byte of a CodeDirectory.
    var codeDirectoryType: UInt8 { self == .sha1 ? 1 : 2 }
    var size: Int { self == .sha1 ? 20 : 32 }

    func hash(_ data: Data) -> Data {
        switch self {
        case .sha1: return Data(Insecure.SHA1.hash(data: data))
        case .sha256: return Data(SHA256.hash(data: data))
        }
    }
}

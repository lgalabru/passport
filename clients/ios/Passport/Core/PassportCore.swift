import Foundation
import PassportFFI

/// The three MRZ fields that unlock the chip with BAC.
struct DocumentKey: Codable, Equatable, Sendable {
    /// As typed or scanned; the Rust core normalises it (upper-case, `<` padding).
    var documentNumber: String
    /// `YYMMDD`.
    var dateOfBirth: String
    /// `YYMMDD`.
    var dateOfExpiry: String

    /// The ICAO Doc 9303 specimen, which the built-in demo chip answers to.
    static let specimen = DocumentKey(documentNumber: "L898902C3", dateOfBirth: "740812", dateOfExpiry: "120415")
}

/// What a file on the chip is addressed as: `EF.COM` or a data group.
enum ChipFile: Hashable, Codable, Sendable, Identifiable {
    case com
    case dg(Int)

    var id: Int { Int(code) }

    /// The code `passport_read` takes: 0 for `EF.COM`, `n` for DG*n*.
    var code: UInt8 {
        switch self {
        case .com: 0
        case .dg(let n): UInt8(n)
        }
    }

    var shortName: String {
        switch self {
        case .com: "COM"
        case .dg(let n): "DG\(n)"
        }
    }

    var title: String {
        switch self {
        case .com: "Index"
        case .dg(let n): DataGroupInfo.title(n)
        }
    }
}

/// Human descriptions of the ICAO 9303 data groups.
enum DataGroupInfo {
    static func title(_ n: Int) -> String {
        switch n {
        case 1: "Machine readable zone"
        case 2: "Face"
        case 3: "Fingerprints"
        case 4: "Iris"
        case 5: "Portrait (displayed)"
        case 6: "Reserved"
        case 7: "Signature"
        case 8, 9, 10: "Data features"
        case 11: "Personal details"
        case 12: "Document details"
        case 13: "Optional details"
        case 14: "Security options"
        case 15: "Active Authentication key"
        case 16: "Persons to notify"
        default: "Data group \(n)"
        }
    }

    static func symbol(_ n: Int) -> String {
        switch n {
        case 1: "text.viewfinder"
        case 2, 5: "person.crop.square"
        case 3: "touchid"
        case 4: "eye"
        case 7: "signature"
        case 11: "person.text.rectangle"
        case 12: "doc.text"
        case 14: "lock.shield"
        case 15: "key"
        case 16: "person.2"
        default: "square.stack.3d.up"
        }
    }

    /// Fingerprints and iris sit behind Extended Access Control, which only
    /// state inspection systems hold.
    static func needsEAC(_ n: Int) -> Bool { n == 3 || n == 4 }
}

/// DG1 decoded by the Rust core.
struct MRZRecord: Codable, Equatable, Sendable {
    var format: String
    var documentCode: String
    var kind: String
    var issuingState: String
    var nationality: String
    var name: String
    var documentNumber: String
    var dateOfBirth: String
    var dateOfExpiry: String
    var gender: String
    var personalNumber: String
    var optionalData: String
    var lines: [String]
    var failedChecks: [String]

    /// `ERIKSSON  ANNA MARIA`: the MRZ separates surname and given names with `<<`.
    var surname: String {
        name.components(separatedBy: "  ").first?.trimmingCharacters(in: .whitespaces) ?? name
    }

    var givenNames: String {
        let parts = name.components(separatedBy: "  ")
        return parts.dropFirst().joined(separator: " ").trimmingCharacters(in: .whitespaces)
    }
}

struct COMInfo: Codable, Equatable, Sendable {
    var ldsVersion: String
    var unicodeVersion: String
    var dataGroups: [Int]
}

enum ReadOutcome: Equatable, Sendable {
    case com(COMInfo?, raw: Data)
    case dg1(MRZRecord?, raw: Data)
    case saved(name: String, bytes: Int, format: String)
}

struct ReadFailure: Error, Equatable, Sendable {
    var error: String
    var hint: String?
    var retryable: Bool
    var statusWord: String?

    var message: String { hint ?? error }
}

/// One progress event from the reader state machine.
enum ReaderEvent: Equatable, Sendable {
    case scanning
    case detected(protocol: String)
    case authenticated
    case reading(offset: Int, total: Int, exchanges: Int)
    case finished(exchanges: Int)
    case failed(String)
}

/// Result of `passport_key_info`: the normalised key and its check digits.
struct KeyInfo: Codable, Equatable, Sendable {
    var ok: Bool
    var documentNumber: String?
    var dateOfBirth: String?
    var dateOfExpiry: String?
    var checkDigits: [String]?
    var mrz: String?
    var error: String?
    var field: String?
}

/// Swift face of `crates/ffi`.
enum PassportCore {
    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    /// Takes ownership of a string returned by the Rust core.
    private static func take(_ pointer: UnsafeMutablePointer<CChar>?) -> Data {
        guard let pointer else { return Data() }
        defer { passport_string_free(pointer) }
        return Data(String(cString: pointer).utf8)
    }

    static func keyInfo(_ key: DocumentKey) -> KeyInfo {
        let data = take(passport_key_info(key.documentNumber, key.dateOfBirth, key.dateOfExpiry))
        return (try? decoder.decode(KeyInfo.self, from: data))
            ?? KeyInfo(ok: false, error: "Invalid key")
    }

    /// Parses an 88/90 character MRZ from the camera; `nil` when it does not decode.
    static func parseMRZ(_ text: String) -> MRZRecord? {
        struct Parsed: Decodable { var ok: Bool; var record: MRZRecord? }
        let data = take(passport_parse_mrz(text))
        return (try? decoder.decode(Parsed.self, from: data))?.record
    }

    static func decodeEvent(_ json: String) -> ReaderEvent? {
        struct Raw: Decodable {
            var kind: String
            var `protocol`: String?
            var offset: Int?
            var total: Int?
            var exchanges: Int?
            var error: String?
        }
        guard let raw = try? decoder.decode(Raw.self, from: Data(json.utf8)) else { return nil }
        switch raw.kind {
        case "scanning": return .scanning
        case "detected": return .detected(protocol: raw.protocol ?? "4a")
        case "authenticated": return .authenticated
        case "reading": return .reading(offset: raw.offset ?? 0, total: raw.total ?? 0, exchanges: raw.exchanges ?? 0)
        case "finished": return .finished(exchanges: raw.exchanges ?? 0)
        case "failed": return .failed(raw.error ?? "Failed")
        default: return nil
        }
    }

    static func decodeResult(_ data: Data) -> Result<ReadOutcome, ReadFailure> {
        struct Raw: Decodable {
            struct Outcome: Decodable {
                var kind: String
                var rawHex: String?
                var com: COMInfo?
                var record: MRZRecord?
                var name: String?
                var bytes: Int?
                var format: String?
            }
            var ok: Bool
            var outcome: Outcome?
            var error: String?
            var hint: String?
            var retryable: Bool?
            var statusWord: String?
        }
        guard let raw = try? decoder.decode(Raw.self, from: data) else {
            return .failure(ReadFailure(error: "Unreadable reader result", retryable: false))
        }
        guard raw.ok, let outcome = raw.outcome else {
            return .failure(ReadFailure(
                error: raw.error ?? "Read failed",
                hint: raw.hint,
                retryable: raw.retryable ?? false,
                statusWord: raw.statusWord
            ))
        }
        let bytes = Data(hex: outcome.rawHex ?? "")
        switch outcome.kind {
        case "com": return .success(.com(outcome.com, raw: bytes))
        case "dg1": return .success(.dg1(outcome.record, raw: bytes))
        default:
            return .success(.saved(name: outcome.name ?? "", bytes: outcome.bytes ?? 0, format: outcome.format ?? "bin"))
        }
    }

    /// One blocking read through `host`. `demoDelay` selects the built-in
    /// specimen chip instead of the host's radio.
    static func read(
        host: UnsafePointer<PassportHost>,
        key: DocumentKey,
        file: ChipFile,
        demoDelay: UInt32?
    ) -> Result<ReadOutcome, ReadFailure> {
        let pointer: UnsafeMutablePointer<CChar>?
        if let demoDelay {
            pointer = passport_demo_read(host, key.documentNumber, key.dateOfBirth, key.dateOfExpiry, file.code, demoDelay)
        } else {
            pointer = passport_read(host, key.documentNumber, key.dateOfBirth, key.dateOfExpiry, file.code)
        }
        return decodeResult(take(pointer))
    }
}

extension Data {
    init(hex: String) {
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex, let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) {
            if let byte = UInt8(hex[index..<next], radix: 16) { data.append(byte) }
            index = next
        }
        self = data
    }

    var hexString: String { map { String(format: "%02X", $0) }.joined() }
}

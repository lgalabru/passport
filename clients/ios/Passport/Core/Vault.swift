import Foundation
import Security

/// The enrolled document: what the chip said, and what proofs are made from.
struct Identity: Codable, Equatable {
    var record: MRZRecord
    /// DG1 exactly as read; the circuit's private input.
    var dg1Hex: String
    /// The BAC key, to read the chip again.
    var key: DocumentKey
    var portraitFile: String?
    var commitment: String
    var enrolledAt: Date
    /// Read from the built-in specimen chip rather than a real document.
    var sample: Bool
}

/// One answered request, for the person's own record.
struct Presentation: Codable, Equatable, Identifiable {
    struct Shared: Codable, Equatable, Hashable {
        var label: String
        var display: String
    }

    var id = UUID()
    var verifier: String
    var recipient: String
    var date: Date
    var shared: [Shared]
    var token: String
    var millis: Int
}

/// Persistence. The holder secret is a Keychain item bound to this device;
/// everything else lives in Application Support under complete file protection.
enum Vault {
    private static let service = "org.solana.passport"

    private static var support: URL {
        let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static var readsDirectory: URL { support.appendingPathComponent("Reads", isDirectory: true) }
    private static var identityURL: URL { support.appendingPathComponent("identity.json") }
    private static var historyURL: URL { support.appendingPathComponent("history.json") }

    // MARK: Keychain

    private static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }

    private static func load(_ account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess ? item as? Data : nil
    }

    private static func store(_ data: Data, _ account: String) {
        SecItemDelete(query(account) as CFDictionary)
        var q = query(account)
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        q[kSecValueData as String] = data
        SecItemAdd(q as CFDictionary, nil)
    }

    /// The holder secret behind the registry commitment, created on first use.
    /// It never leaves the device: proofs show knowledge of it, not the value.
    static func secretHex(create: Bool) -> String? {
        if let data = load("holder-secret") { return data.hexString }
        guard create else { return nil }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        // Keep it below the BN254 order without bias worth mentioning.
        bytes[0] &= 0x1F
        store(Data(bytes), "holder-secret")
        return Data(bytes).hexString
    }

    // MARK: Files

    private static func read<T: Decodable>(_ url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(T.self, from: data)
    }

    private static func write<T: Encodable>(_ value: T, _ url: URL) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(value) else { return }
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    static func loadIdentity() -> Identity? { read(identityURL) }
    static func save(_ identity: Identity) { write(identity, identityURL) }
    static func loadHistory() -> [Presentation] { read(historyURL) ?? [] }
    static func save(_ history: [Presentation]) { write(history, historyURL) }

    static func portraitURL(_ identity: Identity) -> URL? {
        identity.portraitFile.map { readsDirectory.appendingPathComponent($0) }
    }

    /// Forget the document, its secret and every record of sharing.
    static func wipe() {
        SecItemDelete(query("holder-secret") as CFDictionary)
        for url in [identityURL, historyURL, readsDirectory] {
            try? FileManager.default.removeItem(at: url)
        }
    }
}

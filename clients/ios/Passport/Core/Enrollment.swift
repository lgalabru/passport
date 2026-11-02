import CryptoKit
import Foundation
import os
import PassportFFI

/// Whether a read passport can enroll, as `passport_enroll_check` reports it.
struct Compatibility: Codable, Equatable, Hashable {
    struct Check: Codable, Equatable, Hashable, Identifiable {
        var id: String
        var label: String
        /// `nil`: not run, an earlier check failed.
        var passed: Bool?
        var detail: String
    }

    var enrollable: Bool
    var issuingState: String
    var documentSigner: String?
    var chipKey: String?
    var checks: [Check]
}

/// The document's enrollment in the on-chain registry.
struct OnChainEnrollment: Codable, Equatable {
    var programId: String
    var signature: String
    var commitment: String
    var enrolledAt: Date
}

struct EnrollmentError: LocalizedError, Equatable {
    var message: String
    var errorDescription: String? { message }
}

private let decoder: JSONDecoder = {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return decoder
}()

private func decode<T: Decodable>(_ type: T.Type, _ object: Any) throws -> T {
    try decoder.decode(T.self, from: JSONSerialization.data(withJSONObject: object))
}

func jsonString(_ object: Any) -> String {
    (try? JSONSerialization.data(withJSONObject: object)).map { String(decoding: $0, as: UTF8.self) } ?? "{}"
}

/// Swift face of `crates/ffi/src/enroll.rs`.
enum EnrollmentCore {
    /// The Active Authentication challenge this enrollment needs signed.
    static func challenge(dg1Hex: String, dg15Hex: String, sodHex: String, secretHex: String) -> String? {
        (try? Attestation.call(passport_enroll_prepare(dg1Hex, dg15Hex, sodHex, secretHex)))?["challenge"] as? String
    }

    static func check(
        dg1Hex: String, dg15Hex: String, sodHex: String, secretHex: String,
        activeAuthentication: ActiveAuthentication?
    ) throws -> Compatibility {
        let object = try Attestation.call(passport_enroll_check(
            dg1Hex, dg15Hex, sodHex, secretHex,
            activeAuthentication?.challenge ?? "", activeAuthentication?.signature ?? ""
        ))
        return try decode(Compatibility.self, object)
    }

    struct Proof {
        var instruction: String
        var commitment: String
        var millis: Int
    }

    /// Load, prove, unload: the 450 MB circuit is only in memory for this.
    static func prove(
        artifacts: URL, dg1Hex: String, dg15Hex: String, sodHex: String, secretHex: String,
        aaHex: String, signerList: String
    ) async throws -> Proof {
        try await Task.detached(priority: .userInitiated) {
            defer { passport_enroll_prover_unload() }
            _ = try Attestation.call(passport_enroll_prover_load(artifacts.path))
            let object = try Attestation.call(passport_enroll_prove(dg1Hex, dg15Hex, sodHex, secretHex, aaHex, signerList))
            return Proof(
                instruction: object["instruction"] as? String ?? "",
                commitment: object["commitment"] as? String ?? "",
                millis: object["millis"] as? Int ?? 0
            )
        }.value
    }

    static func transaction(programId: String, feePayer: String, blockhash: String, instruction: String) throws -> String {
        try Attestation.call(passport_enroll_transaction(programId, feePayer, blockhash, instruction))["transaction"] as? String ?? ""
    }

    static func registryAddress(_ programId: String) throws -> String {
        try Attestation.call(passport_registry_address(programId))["address"] as? String ?? ""
    }
}

/// JSON-RPC 2.0 over HTTPS: Solana's and Kora's.
struct JSONRPC {
    var url: URL

    func call(_ method: String, _ params: Any) async throws -> Any {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        ])
        request.timeoutInterval = 30
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw EnrollmentError(message: "\(url.host() ?? "The server") did not answer \(method).")
        }
        if let error = object["error"] as? [String: Any] {
            throw EnrollmentError(message: error["message"] as? String ?? "\(method) failed")
        }
        return object["result"] ?? NSNull()
    }
}

/// The Solana calls the app makes, at `confirmed`.
struct Solana {
    var rpc: JSONRPC

    func accountData(_ address: String) async throws -> String? {
        let result = try await rpc.call("getAccountInfo", [address, ["encoding": "base64", "commitment": "confirmed"]])
        let value = (result as? [String: Any])?["value"] as? [String: Any]
        return (value?["data"] as? [Any])?.first as? String
    }

    /// Signatures touching `address`, newest first, back to (not including) `until`.
    func signatures(for address: String, until: String?) async throws -> [(signature: String, failed: Bool)] {
        var out: [(String, Bool)] = []
        var before: String?
        while true {
            var options: [String: Any] = ["limit": 1000, "commitment": "confirmed"]
            if let until { options["until"] = until }
            if let before { options["before"] = before }
            let page = try await rpc.call("getSignaturesForAddress", [address, options]) as? [[String: Any]] ?? []
            for entry in page {
                guard let signature = entry["signature"] as? String else { continue }
                out.append((signature, !(entry["err"] is NSNull || entry["err"] == nil)))
            }
            guard page.count == 1000, let last = out.last?.0 else { return out }
            before = last
        }
    }

    func logs(_ signature: String) async throws -> [String] {
        let result = try await rpc.call("getTransaction", [signature, [
            "encoding": "json", "commitment": "confirmed", "maxSupportedTransactionVersion": 0,
        ]])
        let meta = (result as? [String: Any])?["meta"] as? [String: Any]
        return meta?["logMessages"] as? [String] ?? []
    }

    /// Waits until `signature` is confirmed; throws if it failed.
    func confirm(_ signature: String, timeout: Duration = .seconds(90)) async throws {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            let result = try await rpc.call("getSignatureStatuses", [[signature], ["searchTransactionHistory": true]])
            if let status = ((result as? [String: Any])?["value"] as? [Any])?.first as? [String: Any] {
                if let err = status["err"], !(err is NSNull) {
                    throw EnrollmentError(message: "The registry refused the enrollment: \(err)")
                }
                let level = status["confirmationStatus"] as? String
                if level == "confirmed" || level == "finalized" { return }
            }
            try await Task.sleep(for: .seconds(1))
        }
        throw EnrollmentError(message: "The enrollment was sent but not confirmed in time. It may still land; check again later.")
    }
}

/// Kora, the fee-payer relayer: it signs the app's unsigned transaction as
/// fee payer and sends it, so no wallet of the holder's appears on-chain.
struct Relayer {
    var rpc: JSONRPC

    func feePayer() async throws -> String {
        let result = try await rpc.call("getPayerSigner", [String: Any]()) as? [String: Any]
        guard let address = result?["signer_address"] as? String else {
            throw EnrollmentError(message: "The relayer did not name its fee payer.")
        }
        return address
    }

    func blockhash() async throws -> String {
        let result = try await rpc.call("getBlockhash", [String: Any]()) as? [String: Any]
        guard let hash = result?["blockhash"] as? String else {
            throw EnrollmentError(message: "The relayer did not give a blockhash.")
        }
        return hash
    }

    func signAndSend(_ transaction: String) async throws -> String {
        let result = try await rpc.call("signAndSendTransaction", ["transaction": transaction]) as? [String: Any]
        guard let signature = result?["signature"] as? String else {
            throw EnrollmentError(message: "The relayer did not send the enrollment.")
        }
        return signature
    }
}

/// The registry as a claim proof needs it: every leaf, in order, and the
/// account's recent roots. Enrollments are cached, so a sync only reads the
/// transactions since the last one.
enum RegistrySync {
    struct View {
        var leaves: [String]
        var recentRoots: [String]
        var signerRoots: [String]

        func json(programId: String) -> String {
            jsonString(["program_id": programId, "leaves": leaves, "recent_roots": recentRoots])
        }
    }

    private struct Cache: Codable {
        var programId: String
        var newest: String?
        var leaves: [Int: String] = [:]
    }

    private struct State: Decodable {
        var enrolled: Int
        var recentRoots: [String]
        var dscRoots: [String]
    }

    private static func cacheURL(_ programId: String) -> URL {
        Vault.cachesDirectory.appendingPathComponent("registry-\(programId).json")
    }

    static func state(_ config: RegistryConfig) async throws -> (enrolled: Int, recentRoots: [String], signerRoots: [String]) {
        guard let rpc = config.rpc else { throw EnrollmentError(message: "No Solana endpoint is configured.") }
        let solana = Solana(rpc: JSONRPC(url: rpc))
        guard let data = try await solana.accountData(EnrollmentCore.registryAddress(config.programId)) else {
            throw EnrollmentError(message: "The registry is not deployed on this cluster.")
        }
        let state = try decode(State.self, Attestation.call(passport_registry_state(data)))
        return (state.enrolled, state.recentRoots, state.dscRoots)
    }

    static func sync(_ config: RegistryConfig) async throws -> View {
        guard let rpc = config.rpc else { throw EnrollmentError(message: "No Solana endpoint is configured.") }
        let solana = Solana(rpc: JSONRPC(url: rpc))
        let registry = try EnrollmentCore.registryAddress(config.programId)
        let url = cacheURL(config.programId)
        var cache = (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode(Cache.self, from: $0) }
            ?? Cache(programId: config.programId)

        for _ in 0..<3 {
            // Transactions first, then the account: the account never has
            // fewer enrollments than the logs read before it.
            let new = try await solana.signatures(for: registry, until: cache.newest)
            var logs: [[String]] = []
            for entry in new.reversed() where !entry.failed {
                logs.append(try await solana.logs(entry.signature))
            }
            let found = try Attestation.call(passport_registry_enrollments(jsonString(logs), config.programId))
            for case let e as [String: Any] in found["enrollments"] as? [Any] ?? [] {
                if let index = e["index"] as? Int, let leaf = e["commitment"] as? String { cache.leaves[index] = leaf }
            }
            if let newest = new.first?.signature { cache.newest = newest }
            try? JSONEncoder().encode(cache).write(to: url, options: .atomic)

            let state = try await self.state(config)
            let leaves = (0..<state.enrolled).compactMap { cache.leaves[$0] }
            if leaves.count == state.enrolled {
                return View(leaves: leaves, recentRoots: state.recentRoots, signerRoots: state.signerRoots)
            }
            if new.isEmpty {
                throw EnrollmentError(message: "This Solana endpoint no longer has the registry's full history; try another.")
            }
        }
        throw EnrollmentError(message: "The registry kept changing while it was read; try again.")
    }
}

/// The enrollment circuit (some 450 MB), downloaded once and checked
/// against the hashes in `manifest.json`:
/// `{"files":[{"name":"pk.bin","sha256":"…","bytes":…},…]}`.
enum EnrollArtifacts {
    struct Manifest: Decodable {
        struct File: Decodable {
            var name: String
            var sha256: String
            var bytes: Int64
        }

        var files: [File]
    }

    static var directory: URL {
        let url = Vault.supportDirectory.appendingPathComponent("EnrollCircuit", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutable = url
        try? mutable.setResourceValues(values)
        return url
    }

    /// Downloads what is missing; `progress` gets the overall fraction.
    static func ensure(from location: URL, progress: @escaping @Sendable (Double) -> Void) async throws -> URL {
        let (data, response) = try await URLSession.shared.data(from: location.appendingPathComponent("manifest.json"))
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw EnrollmentError(message: "The enrollment circuit is not available for download.")
        }
        let manifest = try JSONDecoder().decode(Manifest.self, from: data)
        for name in ["circuit.xbc", "matrices.bin", "pk.bin"] where !manifest.files.contains(where: { $0.name == name }) {
            throw EnrollmentError(message: "The enrollment circuit's manifest has no \(name).")
        }
        let total = max(1, Double(manifest.files.map(\.bytes).reduce(0, +)))
        var done: Int64 = 0
        let dir = directory
        for file in manifest.files {
            guard !file.name.contains("/"), !file.name.hasPrefix(".") else {
                throw EnrollmentError(message: "The manifest names an unexpected file.")
            }
            let target = dir.appendingPathComponent(file.name)
            let marker = dir.appendingPathComponent(".\(file.name).sha256")
            let size = (try? FileManager.default.attributesOfItem(atPath: target.path))?[.size] as? Int64
            if (try? String(contentsOf: marker, encoding: .utf8)) == file.sha256, size == file.bytes {
                done += file.bytes
                progress(Double(done) / total)
                continue
            }
            let before = Double(done)
            let delegate = ProgressDelegate { fraction in
                progress((before + fraction * Double(file.bytes)) / total)
            }
            let (downloaded, response) = try await URLSession.shared.download(
                from: location.appendingPathComponent(file.name), delegate: delegate
            )
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                throw EnrollmentError(message: "\(file.name) could not be downloaded.")
            }
            guard try sha256(of: downloaded) == file.sha256.lowercased() else {
                try? FileManager.default.removeItem(at: downloaded)
                throw EnrollmentError(message: "\(file.name) arrived damaged; try again.")
            }
            try? FileManager.default.removeItem(at: target)
            try FileManager.default.moveItem(at: downloaded, to: target)
            try file.sha256.write(to: marker, atomically: true, encoding: .utf8)
            done += file.bytes
            progress(Double(done) / total)
        }
        return dir
    }

    static func remove() {
        try? FileManager.default.removeItem(at: directory)
    }

    private static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 4 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

/// Reports a download's progress through the task's `Progress`.
private final class ProgressDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let report: @Sendable (Double) -> Void
    private var observation: NSKeyValueObservation?

    init(report: @escaping @Sendable (Double) -> Void) {
        self.report = report
    }

    func urlSession(_ session: URLSession, didCreateTask task: URLSessionTask) {
        observation = task.progress.observe(\.fractionCompleted) { [report] progress, _ in
            report(progress.fractionCompleted)
        }
    }
}

/// Proving enrollment peaks near 2 GB. With the increased-memory-limit
/// entitlement recent iPhones allow that; older ones do not, and are told
/// so instead of being killed mid-proof.
enum MemoryCheck {
    static let needed = 2_300_000_000

    /// `nil` if enough is free (or this is a simulator, which reports 0).
    static func shortfall() -> String? {
        let available = os_proc_available_memory()
        guard available > 0, available < needed else { return nil }
        let gb = { (n: Int) in String(format: "%.1f GB", Double(n) / 1_000_000_000) }
        return "Enrolling needs about \(gb(needed)) of memory and this iPhone can give Passport \(gb(available)). Close other apps and try again; older iPhones cannot enroll on the device yet."
    }
}

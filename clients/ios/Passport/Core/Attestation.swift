import Foundation
import PassportFFI

/// A relying party's OpenID4VP request, as the Rust core parsed it.
struct VerificationRequest: Equatable, Identifiable {
    struct Claim: Decodable, Equatable, Hashable {
        var path: [String]
        var label: String
        var discloses: Bool
    }

    let id = UUID()
    var clientId: String
    var clientName: String?
    var logoUri: String?
    var purpose: String?
    /// Host of the response URI: who receives the proof.
    var recipient: String
    var responseUri: String
    var claims: [Claim]
    /// The request as the core serialised it; handed back to prove.
    var json: String

    /// What to call the relying party on screen: the host that receives the
    /// proof. `clientName` and `logoUri` are whatever the request says, so
    /// they never stand in for it.
    var displayName: String { recipient }

    static func == (a: Self, b: Self) -> Bool { a.json == b.json }
}

/// A requested claim with the value the proof would carry.
struct ClaimPreview: Decodable, Equatable, Hashable {
    var label: String
    var display: String
    var discloses: Bool
}

struct AttestationError: LocalizedError, Equatable {
    var message: String
    var unsupported = false
    var errorDescription: String? { message }
}

/// Swift face of `crates/ffi/src/attest.rs`, plus the network legs of OpenID4VP.
enum Attestation {
    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    static func call(_ pointer: UnsafeMutablePointer<CChar>?) throws -> [String: Any] {
        guard let pointer else { throw AttestationError(message: "No answer from the core") }
        defer { passport_string_free(pointer) }
        let data = Data(String(cString: pointer).utf8)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AttestationError(message: "Unreadable answer from the core")
        }
        guard object["ok"] as? Bool == true else {
            throw AttestationError(
                message: object["error"] as? String ?? "Failed",
                unsupported: object["unsupported"] as? Bool ?? false
            )
        }
        return object
    }

    private static func request(from object: Any?) throws -> VerificationRequest {
        guard let object = object as? [String: Any] else { throw AttestationError(message: "No request") }
        let data = try JSONSerialization.data(withJSONObject: object)
        struct Raw: Decodable {
            var clientId: String
            var clientName: String?
            var logoUri: String?
            var purpose: String?
            var recipient: String
            var responseUri: String
            var claims: [VerificationRequest.Claim]
        }
        let raw = try decoder.decode(Raw.self, from: data)
        return VerificationRequest(
            clientId: raw.clientId, clientName: raw.clientName, logoUri: raw.logoUri,
            purpose: raw.purpose, recipient: raw.recipient, responseUri: raw.responseUri,
            claims: raw.claims, json: String(decoding: data, as: UTF8.self)
        )
    }

    /// Whether a URL is something this app answers.
    static func handles(_ url: URL) -> Bool {
        ["openid4vp", "passport"].contains(url.scheme?.lowercased() ?? "")
    }

    /// Parse the link, fetching the request object when the link points to one.
    static func resolve(_ url: URL) async throws -> VerificationRequest {
        let parsed = try call(passport_request_parse(url.absoluteString))
        if parsed["kind"] as? String == "inline" {
            return try request(from: parsed["request"])
        }
        guard let uri = (parsed["request_uri"] as? String).flatMap(URL.init(string:)),
              uri.scheme == "https" || uri.host == "localhost" || uri.host == "127.0.0.1" else {
            throw AttestationError(message: "The request link is not secure.")
        }
        var fetch = URLRequest(url: uri)
        fetch.setValue("application/oauth-authz-req+jwt, application/json", forHTTPHeaderField: "Accept")
        if parsed["post"] as? Bool == true {
            fetch.httpMethod = "POST"
            fetch.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            fetch.httpBody = Data()
        }
        let (data, response) = try await URLSession.shared.data(for: fetch)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw AttestationError(message: "The website did not provide its request.")
        }
        let clientId = parsed["client_id"] as? String ?? ""
        let object = try call(passport_request_object(String(decoding: data, as: UTF8.self), clientId))
        return try request(from: object["request"])
    }

    static func loadProver() throws -> String {
        guard let dir = Bundle.main.url(forResource: "Circuit", withExtension: nil) else {
            throw AttestationError(message: "The proving circuit is missing from the app.")
        }
        return try call(passport_prover_load(dir.path))["kid"] as? String ?? ""
    }

    /// The registry commitment of a document, which also validates it can prove.
    static func enroll(dg1Hex: String, secretHex: String) throws -> String {
        try call(passport_enroll(dg1Hex, secretHex))["commitment"] as? String ?? ""
    }

    static func preview(_ request: VerificationRequest, dg1Hex: String, now: Date = Date()) throws -> [ClaimPreview] {
        let object = try call(passport_preview(request.json, dg1Hex, Int64(now.timeIntervalSince1970)))
        let data = try JSONSerialization.data(withJSONObject: object["claims"] ?? [])
        return try decoder.decode([ClaimPreview].self, from: data)
    }

    struct Proof {
        var token: String
        var body: String
        var millis: Int
    }

    /// Prove; blocks for a fraction of a second, so it runs off the main actor.
    static func prove(_ request: VerificationRequest, dg1Hex: String, secretHex: String) async throws -> Proof {
        try await Task.detached(priority: .userInitiated) {
            let object = try call(passport_prove(request.json, dg1Hex, secretHex, Int64(Date().timeIntervalSince1970)))
            return Proof(
                token: object["token"] as? String ?? "",
                body: object["body"] as? String ?? "",
                millis: object["millis"] as? Int ?? 0
            )
        }.value
    }

    /// Prove against the on-chain registry (`registry` from `RegistrySync`).
    static func proveEnrolled(
        _ request: VerificationRequest, dg1Hex: String, dg15Hex: String, sodHex: String,
        secretHex: String, registry: String
    ) async throws -> Proof {
        try await Task.detached(priority: .userInitiated) {
            let object = try call(passport_prove_enrolled(
                request.json, dg1Hex, dg15Hex, sodHex, secretHex, registry, Int64(Date().timeIntervalSince1970)
            ))
            return Proof(
                token: object["token"] as? String ?? "",
                body: object["body"] as? String ?? "",
                millis: object["millis"] as? Int ?? 0
            )
        }.value
    }

    /// `direct_post` to the response URI. Returns where to send the person next,
    /// if the relying party said.
    static func post(_ body: String, to request: VerificationRequest) async throws -> URL? {
        guard let url = URL(string: request.responseUri) else { throw AttestationError(message: "Bad response address") }
        var post = URLRequest(url: url)
        post.httpMethod = "POST"
        post.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        post.httpBody = Data(body.utf8)
        let (data, response) = try await URLSession.shared.data(for: post)
        guard let status = (response as? HTTPURLResponse)?.statusCode, (200..<300).contains(status) else {
            throw AttestationError(message: "\(request.displayName) did not accept the proof.")
        }
        let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (object?["redirect_uri"] as? String).flatMap(URL.init(string:))
    }

    static func decline(_ request: VerificationRequest) async {
        guard let object = try? call(passport_decline_body(request.json)), let body = object["body"] as? String else { return }
        _ = try? await post(body, to: request)
    }
}

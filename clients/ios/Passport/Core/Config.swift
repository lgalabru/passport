import Foundation

/// Where the app's network services are, from Info.plist (`PassportRegistry`
/// dictionary), so a build can point at devnet or a local surfpool without
/// code changes. An empty value turns the feature off with a clear message.
///
/// | Key | What |
/// |---|---|
/// | `ProgramId` | The registry program, base58. |
/// | `RPC` | A Solana JSON-RPC endpoint. |
/// | `Relayer` | A Kora JSON-RPC endpoint that pays for enrollments. |
/// | `Artifacts` | Base URL of the enrollment circuit: `manifest.json` and its files. |
/// | `SignerList` | URL of the publisher's DSC list, `{"leaves":[…]}`. |
struct RegistryConfig: Equatable {
    var programId: String
    var rpc: URL?
    var relayer: URL?
    var artifacts: URL?
    var signerList: URL?

    static let current: RegistryConfig = {
        let dict = Bundle.main.object(forInfoDictionaryKey: "PassportRegistry") as? [String: String] ?? [:]
        let url = { (key: String) -> URL? in
            dict[key].flatMap { $0.isEmpty ? nil : URL(string: $0) }
        }
        return RegistryConfig(
            programId: dict["ProgramId"] ?? "",
            rpc: url("RPC") ?? URL(string: "https://api.devnet.solana.com"),
            relayer: url("Relayer"),
            artifacts: url("Artifacts"),
            signerList: url("SignerList")
        )
    }()

    /// What is missing for on-chain enrollment, if anything.
    var missing: String? {
        if programId.isEmpty { return "No registry is configured in this build." }
        if rpc == nil { return "No Solana endpoint is configured in this build." }
        if relayer == nil { return "No relayer is configured in this build." }
        if artifacts == nil { return "No download location for the enrollment circuit is configured." }
        if signerList == nil { return "No document signer list is configured in this build." }
        return nil
    }
}

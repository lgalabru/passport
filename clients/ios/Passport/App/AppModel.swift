import Foundation
import LocalAuthentication
import Observation
import UIKit

/// Adding a document: key, then the chip.
@Observable
final class Setup {
    enum Step: Equatable {
        case intro, scan, manual, reading, done
    }

    var step: Step = .intro
    var key: DocumentKey?
    var progress: ReadProgress?
    var error: String?
}

/// Enrolling the document in the on-chain registry: download, prove, relay.
@Observable
final class EnrollmentSession {
    enum Phase: Equatable {
        case downloading(Double)
        case proving
        case sending
        case confirming
        case done
        case failed(String)
    }

    var phase: Phase = .downloading(0)
    var proofMillis: Int?

    var isRunning: Bool {
        switch phase {
        case .done, .failed: false
        default: true
        }
    }
}

/// One incoming request, from link to answer.
@Observable
final class RequestSession: Identifiable {
    enum Phase: Equatable {
        case loading
        case review
        case proving
        case sending
        case done(redirect: URL?)
        case declined
        case failed(String)
    }

    let id = UUID()
    let url: URL
    var phase: Phase = .loading
    var request: VerificationRequest?
    var preview: [ClaimPreview] = []

    init(url: URL) {
        self.url = url
    }
}

@Observable
final class AppModel {
    var identity: Identity?
    var history: [Presentation]
    var setup: Setup?
    var session: RequestSession?
    var enrollment: EnrollmentSession?
    let registry = RegistryConfig.current
    /// What the second page shows on an unfolded Duo (and what is pushed on one screen).
    var selection: Selection?

    /// The window is laid out as two pages (an unfolded Duo). Folded, the
    /// app keeps the document to a glanceable minimum.
    var unfolded = false {
        didSet { if !unfolded { revealed = false } }
    }

    /// The details were unlocked on the single screen with Face ID / Touch ID.
    private(set) var revealed = false

    /// Whether the name, photo and details may be on screen.
    var showsPrivateDetails: Bool { unfolded || revealed }

    func reveal() async {
        if await authenticate(reason: "Show your passport details") { revealed = true }
    }

    func conceal() {
        revealed = false
    }

    enum Selection: Hashable {
        case document
        case presentation(UUID)
    }

    /// `-demo` (debug builds): plays the taps of the scripted demo recording.
    /// Setup runs on its own with the sample passport, and a request is
    /// approved once it shows on the right-hand page of an unfolded Duo.
    static let demo: Bool = {
        #if DEBUG
        ProcessInfo.processInfo.arguments.contains("-demo")
        #else
        false
        #endif
    }()

    /// Simulators have no NFC; documents are then read from the built-in
    /// specimen chip.
    let nfcAvailable = NFCLink.isAvailable
    private(set) var proverReady = false
    private(set) var proverError: String?
    private let reader = ChipReader()

    init() {
        identity = Vault.loadIdentity()
        history = Vault.loadHistory()
        Task.detached(priority: .utility) { [weak self] in
            let result = Result { try Attestation.loadProver() }
            await MainActor.run {
                switch result {
                case .success: self?.proverReady = true
                case .failure(let error): self?.proverError = error.localizedDescription
                }
            }
        }
        #if DEBUG
        // `-sample`: enroll the specimen at launch. `-open <url>`: handle a
        // request link at launch. `-auto-share`: approve requests. For
        // screenshots and end-to-end checks on a simulator.
        let arguments = ProcessInfo.processInfo.arguments
        if Self.demo {
            if identity == nil {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.beginSetup() }
            }
            listenForDemoRequests()
        }
        if arguments.contains("-sample"), identity == nil {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.addSample() }
        }
        if let i = arguments.firstIndex(of: "-open"), arguments.indices.contains(i + 1), let url = URL(string: arguments[i + 1]) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { self.open(url) }
        }
        #endif
    }

    #if DEBUG
    /// The demo script delivers its request link without the system's "Open in
    /// Passport?" prompt: it writes `Documents/demo-request.url` and posts the
    /// Darwin notification `org.solana.passport.demo.request`.
    private func listenForDemoRequests() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterAddObserver(center, observer, { _, observer, _, _, _ in
            guard let observer else { return }
            let model = Unmanaged<AppModel>.fromOpaque(observer).takeUnretainedValue()
            DispatchQueue.main.async { model.openDemoRequest() }
        }, "org.solana.passport.demo.request" as CFString, nil, .deliverImmediately)
    }

    private func openDemoRequest() {
        let file = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("demo-request.url")
        guard let text = try? String(contentsOf: file, encoding: .utf8),
              let url = URL(string: text.trimmingCharacters(in: .whitespacesAndNewlines)) else { return }
        open(url)
    }
    #else
    private func listenForDemoRequests() {}
    #endif

    var portrait: UIImage? {
        identity.flatMap(Vault.portraitURL).flatMap(PartialImage.load)
    }

    // MARK: Adding a document

    func beginSetup() {
        setup = Setup()
    }

    /// The specimen passport, read from the software chip.
    func addSample() {
        let setup = self.setup ?? Setup()
        self.setup = setup
        read(.specimen, into: setup, sample: true)
    }

    func read(_ key: DocumentKey, into setup: Setup, sample: Bool = false) {
        setup.key = key
        setup.error = nil
        setup.step = .reading
        let useSample = sample || !nfcAvailable
        // DG1 and the photo for the app; EF.SOD, DG15 and the chip's answer
        // to a challenge for enrollment, all in one tap.
        let progress = ReadProgress(plan: [.dg(1), .dg(2), .sod, .dg(15)], demo: useSample)
        setup.progress = progress
        guard let secret = Vault.secretHex(create: true) else {
            setup.error = "Could not create a key on this iPhone."
            return
        }
        reader.start(
            key: key, plan: progress.plan, demo: useSample, directory: Vault.readsDirectory, progress: progress,
            challenge: { results in
                guard let dg1 = results.dg1, let dg15 = results.files[.dg(15)] else { return nil }
                // The challenge enrollment needs; a random one when this
                // document cannot enroll, so the check still says whether
                // the chip is genuine.
                return EnrollmentCore.challenge(
                    dg1Hex: dg1.hexString, dg15Hex: dg15.hexString,
                    sodHex: results.files[.sod]?.hexString ?? "", secretHex: secret
                ) ?? (0..<8).map { _ in String(format: "%02X", UInt8.random(in: 0...255)) }.joined()
            }
        ) { [weak self] results in
            self?.enroll(results, key: key, secret: secret, setup: setup, sample: useSample)
        }
    }

    func cancelRead() {
        reader.cancel()
    }

    /// `secret` is the one the challenge was derived from: the chip's
    /// answer only fits a commitment to it.
    private func enroll(_ results: ReadResults, key: DocumentKey, secret: String, setup: Setup, sample: Bool) {
        guard let record = results.record, let dg1 = results.dg1 else {
            if case .failed(let failure) = setup.progress?.status {
                setup.error = failure.message
            }
            return
        }
        do {
            let commitment = try Attestation.enroll(dg1Hex: dg1.hexString, secretHex: secret)
            let dg15 = results.files[.dg(15)]?.hexString
            let sod = results.files[.sod]?.hexString
            let compatibility = sod.flatMap { sod in
                try? EnrollmentCore.check(
                    dg1Hex: dg1.hexString, dg15Hex: dg15 ?? "", sodHex: sod, secretHex: secret,
                    activeAuthentication: results.activeAuthentication
                )
            }
            let identity = Identity(
                record: record, dg1Hex: dg1.hexString, key: key,
                portraitFile: results.saved[.dg(2)]?.name, commitment: commitment,
                enrolledAt: Date(), sample: sample,
                dg15Hex: dg15, sodHex: sod,
                activeAuthentication: results.activeAuthentication,
                compatibility: compatibility
            )
            Vault.save(identity)
            self.identity = identity
            setup.step = .done
            if let session, session.phase == .review {
                Task { await self.prepare(session) }
            }
        } catch {
            setup.error = error.localizedDescription
        }
    }

    /// Setup is over: dismiss it and ask to show requests as notifications.
    func finishSetup() {
        setup = nil
        Task {
            await NotificationRouter.shared.requestPermission()
            #if DEBUG
            if Self.demo {
                // Back to the Home screen, where the demo's request notification lands.
                try? await Task.sleep(for: .seconds(1.5))
                let marker = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("demo-home")
                try? Data().write(to: marker)
                // On the main thread: off it, UIKit traps (SIGTRAP in suspend).
                await MainActor.run { _ = UIApplication.shared.perform(Selector(("suspend"))) }
            }
            #endif
        }
    }

    // MARK: Enrolling in the registry

    /// Why this document cannot enroll on-chain from this build, if it cannot.
    var enrollmentBlocker: String? {
        guard let identity else { return "Add a passport first." }
        if identity.onChain != nil { return nil }
        if let missing = registry.missing { return missing }
        guard let compatibility = identity.compatibility else {
            return "Read your passport again: this version also checks the chip's signature."
        }
        if !compatibility.enrollable { return "This passport cannot enroll yet; see Compatibility." }
        return nil
    }

    func enrollOnChain() {
        guard enrollmentBlocker == nil, enrollment?.isRunning != true,
              let identity, let sod = identity.sodHex, let dg15 = identity.dg15Hex,
              let aa = identity.activeAuthentication, let secret = Vault.secretHex(create: false),
              let artifacts = registry.artifacts, let signerList = registry.signerList,
              let relayerURL = registry.relayer, let rpc = registry.rpc else { return }
        let session = EnrollmentSession()
        enrollment = session
        let config = registry
        Task { @MainActor in
            do {
                if let shortfall = MemoryCheck.shortfall() { throw EnrollmentError(message: shortfall) }
                let dir = try await EnrollArtifacts.ensure(from: artifacts) { fraction in
                    Task { @MainActor in session.phase = .downloading(fraction) }
                }
                // The publisher's signer list, and the roots the registry trusts.
                let (list, _) = try await URLSession.shared.data(from: signerList)
                guard var dsc = try JSONSerialization.jsonObject(with: list) as? [String: Any] else {
                    throw EnrollmentError(message: "The document signer list is unreadable.")
                }
                dsc["trusted_roots"] = try await RegistrySync.state(config).signerRoots

                session.phase = .proving
                let proof = try await EnrollmentCore.prove(
                    artifacts: dir, dg1Hex: identity.dg1Hex, dg15Hex: dg15, sodHex: sod,
                    secretHex: secret, aaHex: aa.signature, signerList: jsonString(dsc)
                )
                session.proofMillis = proof.millis

                session.phase = .sending
                let relayer = Relayer(rpc: JSONRPC(url: relayerURL))
                let transaction = try EnrollmentCore.transaction(
                    programId: config.programId, feePayer: try await relayer.feePayer(),
                    blockhash: try await relayer.blockhash(), instruction: proof.instruction
                )
                let signature = try await relayer.signAndSend(transaction)

                session.phase = .confirming
                try await Solana(rpc: JSONRPC(url: rpc)).confirm(signature)

                var enrolled = identity
                enrolled.onChain = OnChainEnrollment(
                    programId: config.programId, signature: signature,
                    commitment: proof.commitment, enrolledAt: Date()
                )
                Vault.save(enrolled)
                self.identity = enrolled
                session.phase = .done
            } catch {
                session.phase = .failed(error.localizedDescription)
            }
        }
    }

    func removeDocument() {
        Vault.wipe()
        identity = nil
        history = []
        selection = nil
    }

    // MARK: Requests

    func open(_ url: URL) {
        guard Attestation.handles(url) else { return }
        let session = RequestSession(url: url)
        self.session = session
        Task { await prepare(session) }
    }

    private func prepare(_ session: RequestSession) async {
        do {
            let request: VerificationRequest
            if let existing = session.request {
                request = existing
            } else {
                request = try await Attestation.resolve(session.url)
            }
            session.request = request
            if let identity {
                session.preview = try Attestation.preview(request, dg1Hex: identity.dg1Hex)
            }
            session.phase = .review
            #if DEBUG
            if ProcessInfo.processInfo.arguments.contains("-auto-share"), identity != nil {
                try? await Task.sleep(for: .seconds(2))
                await share(session)
            }
            #endif
        } catch {
            session.phase = .failed(error.localizedDescription)
        }
    }

    /// Consent given: confirm it is the owner, prove, send.
    func share(_ session: RequestSession) async {
        guard let request = session.request, let identity, let secret = Vault.secretHex(create: false) else { return }
        guard await authenticate(reason: "Share with \(request.displayName)") else { return }
        do {
            session.phase = .proving
            let proof: Attestation.Proof
            if let onChain = identity.onChain, onChain.programId == registry.programId,
               let dg15 = identity.dg15Hex, let sod = identity.sodHex {
                let view = try await RegistrySync.sync(registry)
                proof = try await Attestation.proveEnrolled(
                    request, dg1Hex: identity.dg1Hex, dg15Hex: dg15, sodHex: sod,
                    secretHex: secret, registry: view.json(programId: onChain.programId)
                )
            } else {
                proof = try await Attestation.prove(request, dg1Hex: identity.dg1Hex, secretHex: secret)
            }
            session.phase = .sending
            let redirect = try await Attestation.post(proof.body, to: request)
            let record = Presentation(
                verifier: request.displayName, recipient: request.recipient, date: Date(),
                shared: session.preview.map { .init(label: $0.label, display: $0.display) },
                token: proof.token, millis: proof.millis
            )
            history.insert(record, at: 0)
            Vault.save(history)
            session.phase = .done(redirect: redirect)
        } catch {
            session.phase = .failed(error.localizedDescription)
        }
    }

    func decline(_ session: RequestSession) {
        if let request = session.request {
            Task { await Attestation.decline(request) }
        }
        session.phase = .declined
        dismiss(session)
    }

    func dismiss(_ session: RequestSession) {
        if case .done(let redirect?) = session.phase {
            UIApplication.shared.open(redirect)
        }
        if self.session?.id == session.id { self.session = nil }
    }

    /// Face ID or Touch ID, falling back to the passcode. Devices with none
    /// set up (a fresh simulator) skip the prompt.
    private func authenticate(reason: String) async -> Bool {
        let context = LAContext()
        let policy: LAPolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        guard context.canEvaluatePolicy(policy, error: nil) else { return true }
        return (try? await context.evaluatePolicy(policy, localizedReason: reason)) ?? false
    }
}

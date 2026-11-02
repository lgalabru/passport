import CoreNFC
import Foundation
import Observation
import PassportFFI

/// Live state of one chip session, observed by the UI.
@Observable
final class ReadProgress {
    enum Stage: Int, CaseIterable, Comparable {
        case waiting, detected, authenticated, reading, done

        static func < (a: Stage, b: Stage) -> Bool { a.rawValue < b.rawValue }
    }

    enum Status: Equatable {
        case running
        case succeeded
        case failed(ReadFailure)
        case cancelled
    }

    let plan: [ChipFile]
    let demo: Bool
    var stage: Stage = .waiting
    var status: Status = .running
    var current: ChipFile?
    var completed: [ChipFile] = []
    var skipped: [ChipFile: ReadFailure] = [:]
    /// Bytes of the current file read so far, and its size (0 when unknown).
    var offset = 0
    var total = 0
    var exchanges = 0
    /// APDUs of the reads already finished; each read counts from zero.
    var baseExchanges = 0
    var protocolName: String?
    var log: [LogLine] = []
    var streamedPortrait: Data?
    var message = "Hold your document against the top of your iPhone"
    let startedAt = Date()
    var finishedAt: Date?

    init(plan: [ChipFile], demo: Bool) {
        self.plan = plan
        self.demo = demo
    }

    var fileFraction: Double {
        total > 0 ? min(1, Double(offset) / Double(total)) : 0
    }

    /// Whole-session progress, weighting the portrait (by far the largest file).
    var overallFraction: Double {
        guard status == .running else { return status == .succeeded ? 1 : fileFraction }
        let weight: (ChipFile) -> Double = { $0 == .dg(2) ? 6 : 1 }
        let all = plan.map(weight).reduce(0, +)
        let done = plan.filter { completed.contains($0) || skipped[$0] != nil }.map(weight).reduce(0, +)
        let partial = current.map { weight($0) * fileFraction } ?? 0
        return all > 0 ? (done + partial) / all : 0
    }

    var isRunning: Bool { status == .running }

    fileprivate func append(_ line: LogLine) {
        log.append(line)
        if log.count > 600 { log.removeFirst(log.count - 600) }
    }
}

/// Everything a session read, handed to the app when it ends.
struct ReadResults {
    var com: COMInfo?
    var record: MRZRecord?
    var dg1: Data?
    var saved: [ChipFile: SavedFile] = [:]
    /// The bytes of the saved files enrollment needs (EF.SOD, DG15).
    var files: [ChipFile: Data] = [:]
    var activeAuthentication: ActiveAuthentication?
    var protocolName: String?
}

/// The chip's answer to a challenge, both hex.
struct ActiveAuthentication: Codable, Equatable, Hashable {
    var challenge: String
    var signature: String
}

struct SavedFile: Codable, Equatable, Hashable {
    var name: String
    var bytes: Int
    var format: String
}

/// Runs a list of reads against one card. The Rust reader blocks, so it runs on
/// a worker thread; progress is republished on the main queue.
final class ChipReader {
    private let worker = DispatchQueue(label: "passport.reader", qos: .userInitiated)
    private var link: NFCLink?
    private var cancelled = false
    private var challenge: ((ReadResults) -> String?)?

    /// Files whose bytes are kept in `ReadResults.files`.
    private static let kept: Set<ChipFile> = [.sod, .dg(15)]

    /// Delay per APDU for the demo chip, so the animation has something to show.
    static let demoDelayMs: UInt32 = 9

    /// `challenge`, when given, runs Active Authentication after the files
    /// are read, in the same session, with the challenge it derives from
    /// them (`nil` to skip, e.g. a chip without DG15).
    func start(
        key: DocumentKey,
        plan: [ChipFile],
        demo: Bool,
        directory: URL,
        progress: ReadProgress,
        challenge: ((ReadResults) -> String?)? = nil,
        completion: @escaping (ReadResults) -> Void
    ) {
        self.challenge = challenge
        cancelled = false
        let bridge = HostBridge(directory: directory)
        wire(bridge, to: progress)

        if demo {
            worker.async { [self] in
                main { progress.stage = .detected }
                let results = run(bridge: bridge, key: key, plan: plan, demo: true, progress: progress)
                main { completion(results) }
            }
            return
        }

        let link = NFCLink()
        self.link = link
        bridge.transceive = { [weak link, weak progress] command in
            guard let link else { return .failure(.notPresent) }
            let preview = command.prefix(12).hexString
            main { progress?.append(LogLine(level: .txrx, text: "→ \(preview)\(command.count > 12 ? "…" : "")")) }
            let result = link.transceive(command)
            if case .success(let response) = result {
                let sw = response.suffix(2).hexString
                main { progress?.append(LogLine(level: .txrx, text: "← \(response.count) B · SW \(sw)")) }
            }
            return result
        }
        link.onInvalidated = { [weak progress] error in
            main {
                guard let progress, progress.isRunning else { return }
                let userCancelled = (error as? NFCReaderError)?.code == .readerSessionInvalidationErrorUserCanceled
                progress.status = userCancelled
                    ? .cancelled
                    : .failed(ReadFailure(error: error.localizedDescription, hint: "The NFC session ended before the chip was read.", retryable: true))
                progress.finishedAt = Date()
            }
        }
        link.onConnected = { [self] link in
            bridge.protocolCode = link.protocolCode
            worker.async { [self] in
                main { progress.stage = .detected }
                let results = run(bridge: bridge, key: key, plan: plan, demo: false, progress: progress)
                main { completion(results) }
            }
        }
        link.begin(message: progress.message)
    }

    func cancel() {
        cancelled = true
        link?.fail(message: "Cancelled")
    }

    private func wire(_ bridge: HostBridge, to progress: ReadProgress) {
        bridge.onEvent = { [weak progress, weak bridge] event in
            // Read on the worker thread by the retry logic, so set it here.
            switch event {
            case .scanning: bridge?.authenticated = false
            case .authenticated: bridge?.authenticated = true
            default: break
            }
            main {
                guard let progress else { return }
                switch event {
                case .scanning:
                    progress.offset = 0
                    progress.total = 0
                case .detected(let proto):
                    progress.protocolName = proto == "4b" ? "ISO 14443-4B" : "ISO 14443-4A"
                    progress.stage = max(progress.stage, .detected)
                case .authenticated:
                    progress.stage = max(progress.stage, .authenticated)
                case .reading(let offset, let total, let exchanges):
                    progress.stage = max(progress.stage, .reading)
                    progress.offset = offset
                    if total > 0 { progress.total = total }
                    progress.exchanges = progress.baseExchanges + exchanges
                case .finished(let exchanges):
                    progress.baseExchanges += exchanges
                    progress.exchanges = progress.baseExchanges
                case .failed:
                    break
                }
            }
        }
        bridge.onLog = { [weak progress] line in
            main { progress?.append(line) }
        }
        bridge.onStream = { [weak progress] name, data in
            guard name.contains("-DG2.") else { return }
            main { progress?.streamedPortrait = data }
        }
    }

    /// The whole plan, file by file. Runs on `worker`.
    private func run(bridge: HostBridge, key: DocumentKey, plan: [ChipFile], demo: Bool, progress: ReadProgress) -> ReadResults {
        var results = ReadResults()
        var host = bridge.makeHost()
        var failure: ReadFailure?

        for (index, file) in plan.enumerated() where !cancelled {
            main {
                progress.current = file
                progress.offset = 0
                progress.total = 0
            }
            link?.setMessage(Self.message(for: file, index: index, of: plan.count))

            var attempt = 0
            var outcome: Result<ReadOutcome, ReadFailure>
            repeat {
                outcome = withUnsafePointer(to: &host) { pointer in
                    PassportCore.read(host: pointer, key: key, file: file, demoDelay: demo ? Self.demoDelayMs : nil)
                }
                guard case .failure(let error) = outcome, !demo, !cancelled, attempt < 2 else { break }
                // A radio hiccup, or a chip that wants a fresh field before a
                // second BAC: reset the field and try once more.
                guard error.retryable || index > 0 && !bridge.authenticated else { break }
                attempt += 1
                link?.setMessage("Hold still… reconnecting")
                main { progress.append(LogLine(level: .warn, text: "Retrying \(file.shortName) after: \(error.error)")) }
                guard link?.reconnect() == true else { break }
                bridge.protocolCode = link?.protocolCode ?? 0
                host = bridge.makeHost()
            } while true

            switch outcome {
            case .success(.com(let com, _)):
                results.com = com
                main { progress.completed.append(file) }
            case .success(.dg1(let record, let raw)):
                results.record = record
                results.dg1 = raw
                main { progress.completed.append(file) }
            case .success(.saved(let name, let bytes, let format)):
                results.saved[file] = SavedFile(name: name, bytes: bytes, format: format)
                if Self.kept.contains(file) {
                    results.files[file] = try? Data(contentsOf: bridge.directory.appendingPathComponent(name))
                }
                main { progress.completed.append(file) }
            case .failure(let error):
                // The index and the extra groups are optional; the identity is not.
                if file == .dg(1) || index == 0 && error.statusWord != "6A82" {
                    failure = error
                } else {
                    main { progress.skipped[file] = error }
                }
            }
            if failure != nil { break }
        }

        if failure == nil, !cancelled, let challenge = challenge?(results) {
            link?.setMessage("Checking the chip is genuine…")
            main { progress.append(LogLine(level: .info, text: "Active Authentication, challenge \(challenge)")) }
            var answer = withUnsafePointer(to: &host) { pointer in
                PassportCore.activeAuthenticate(host: pointer, key: key, challengeHex: challenge, demoDelay: demo ? Self.demoDelayMs : nil)
            }
            if case .failure(let error) = answer, error.retryable, !demo, link?.reconnect() == true {
                bridge.protocolCode = link?.protocolCode ?? 0
                host = bridge.makeHost()
                answer = withUnsafePointer(to: &host) { pointer in
                    PassportCore.activeAuthenticate(host: pointer, key: key, challengeHex: challenge, demoDelay: nil)
                }
            }
            switch answer {
            case .success(let signature):
                results.activeAuthentication = ActiveAuthentication(challenge: challenge, signature: signature)
            case .failure(let error):
                // Not fatal: the compatibility check reports it.
                main { progress.append(LogLine(level: .warn, text: "Active Authentication: \(error.error)")) }
            }
        }

        let finalFailure = failure
        main {
            progress.finishedAt = Date()
            progress.current = nil
            if self.cancelled {
                progress.status = .cancelled
            } else if let finalFailure {
                progress.status = .failed(finalFailure)
            } else {
                progress.stage = .done
                progress.status = .succeeded
            }
        }
        if let finalFailure {
            link?.fail(message: finalFailure.message)
        } else {
            link?.finish(message: "Done ✓")
        }
        results.protocolName = bridge.protocolCode == 1 ? "ISO 14443-4B" : "ISO 14443-4A"
        return results
    }

    private static func message(for file: ChipFile, index: Int, of count: Int) -> String {
        let step = "\(index + 1)/\(count)"
        switch file {
        case .com: return "Opening the chip… \(step)"
        case .dg(1): return "Reading your details… \(step)"
        case .dg(2): return "Reading your photo… keep still \(step)"
        case .sod: return "Reading the issuer's signature… \(step)"
        default: return "Reading \(file.shortName)… \(step)"
        }
    }
}

private func main(_ work: @escaping () -> Void) {
    DispatchQueue.main.async(execute: work)
}

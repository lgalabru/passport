import CoreNFC
import Foundation

/// A CoreNFC session holding one ISO 7816 tag, exposed as a blocking
/// transceive for the Rust reader's worker thread.
final class NFCLink: NSObject, NFCTagReaderSessionDelegate {
    static var isAvailable: Bool { NFCTagReaderSession.readingAvailable }

    /// Called once, on the NFC queue, when the first tag is connected.
    var onConnected: ((NFCLink) -> Void)?
    /// Called when the session ends without `finish` (cancel, timeout, error).
    var onInvalidated: ((Error) -> Void)?

    private var session: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private let queue = DispatchQueue(label: "passport.nfc", qos: .userInitiated)
    private var reconnecting: DispatchSemaphore?
    private var finished = false
    private var connectedOnce = false

    /// `14443-4B` cards answer with application data, `-4A` with historical bytes.
    var protocolCode: UInt8 { tag?.applicationData != nil ? 1 : 0 }

    func begin(message: String) {
        guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: queue) else {
            onInvalidated?(NFCReaderError(.readerErrorUnsupportedFeature))
            return
        }
        session.alertMessage = message
        self.session = session
        session.begin()
    }

    func setMessage(_ message: String) {
        session?.alertMessage = message
    }

    func finish(message: String) {
        finished = true
        session?.alertMessage = message
        session?.invalidate()
    }

    func fail(message: String) {
        finished = true
        session?.invalidate(errorMessage: message)
    }

    /// One APDU exchange. Blocks the calling thread; never call it on `queue`.
    func transceive(_ command: Data, timeout: TimeInterval = 6) -> Result<Data, TransceiveCode> {
        guard let tag, tag.isAvailable else { return .failure(.notPresent) }
        guard let apdu = NFCISO7816APDU(data: command) else { return .failure(.protocolError) }
        let done = DispatchSemaphore(value: 0)
        var result: Result<Data, TransceiveCode> = .failure(.timeout)
        tag.sendCommand(apdu: apdu) { response, sw1, sw2, error in
            if let error {
                result = .failure(Self.code(for: error))
            } else {
                var data = response
                data.append(contentsOf: [sw1, sw2])
                result = .success(data)
            }
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success else { return .failure(.timeout) }
        return result
    }

    /// Drop the field and wait for the card again: some chips only accept a
    /// fresh BAC after a reset. `false` when no card came back in time.
    func reconnect(timeout: TimeInterval = 8) -> Bool {
        guard let session else { return false }
        let wait = DispatchSemaphore(value: 0)
        reconnecting = wait
        session.restartPolling()
        let ok = wait.wait(timeout: .now() + timeout) == .success
        reconnecting = nil
        return ok
    }

    private static func code(for error: Error) -> TransceiveCode {
        guard let error = error as? NFCReaderError else { return .io }
        switch error.code {
        case .readerTransceiveErrorTagConnectionLost, .readerTransceiveErrorTagNotConnected:
            return .notPresent
        case .readerTransceiveErrorRetryExceeded:
            return .timeout
        case .readerTransceiveErrorTagResponseError, .readerTransceiveErrorPacketTooLong:
            return .protocolError
        default:
            return .io
        }
    }

    // MARK: NFCTagReaderSessionDelegate

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
        tag = nil
        reconnecting?.signal()
        if !finished {
            finished = true
            onInvalidated?(error)
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        if tags.count > 1 {
            session.alertMessage = "More than one card found. Hold just your document."
            session.restartPolling()
            return
        }
        guard case .iso7816(let found)? = tags.first else {
            session.alertMessage = "This card is not a passport or ID card."
            session.restartPolling()
            return
        }
        session.connect(to: tags[0]) { [weak self] error in
            guard let self else { return }
            if let error {
                session.alertMessage = "Lost the chip: \(error.localizedDescription). Hold still."
                session.restartPolling()
                return
            }
            self.tag = found
            if let reconnecting = self.reconnecting {
                reconnecting.signal()
            } else if !self.connectedOnce {
                self.connectedOnce = true
                self.onConnected?(self)
            }
        }
    }
}

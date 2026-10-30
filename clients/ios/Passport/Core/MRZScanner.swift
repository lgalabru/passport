import AVFoundation
import Observation
import UIKit
import Vision

/// Finds the BAC key in camera frames of a document's photo page.
///
/// Only the fields the chip needs are trusted: document number, birth and
/// expiry dates, each with its check digit verified by the Rust core. A key is
/// accepted once two consecutive frames agree.
@Observable
final class MRZScanner: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    enum State: Equatable {
        case starting, scanning, unavailable(String), found
    }

    var state: State = .starting
    /// Best MRZ-looking lines in the latest frame, for the live overlay.
    var lines: [String] = []
    /// Which of the three check digits verified in the latest frame.
    var checks: [Bool] = [false, false, false]
    var found: DocumentKey?
    var record: MRZRecord?

    let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "passport.mrz", qos: .userInitiated)
    private var busy = false
    private var lastFrame = Date.distantPast
    private var candidate: DocumentKey?

    func start() {
        guard AVCaptureDevice.default(for: .video) != nil else {
            state = .unavailable("No camera on this device.")
            return
        }
        AVCaptureDevice.requestAccess(for: .video) { granted in
            DispatchQueue.main.async {
                guard granted else {
                    self.state = .unavailable("Camera access is off. Enable it in Settings, or type the details.")
                    return
                }
                self.queue.async { self.configure() }
            }
        }
    }

    func stop() {
        queue.async { if self.session.isRunning { self.session.stopRunning() } }
    }

    private func configure() {
        guard session.inputs.isEmpty else {
            session.startRunning()
            return
        }
        session.beginConfiguration()
        session.sessionPreset = .hd1920x1080
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else {
            session.commitConfiguration()
            DispatchQueue.main.async { self.state = .unavailable("The camera could not start.") }
            return
        }
        session.addInput(input)
        let output = AVCaptureVideoDataOutput()
        output.alwaysDiscardsLateVideoFrames = true
        output.setSampleBufferDelegate(self, queue: queue)
        if session.canAddOutput(output) { session.addOutput(output) }
        session.commitConfiguration()
        if (try? device.lockForConfiguration()) != nil {
            if device.isFocusModeSupported(.continuousAutoFocus) { device.focusMode = .continuousAutoFocus }
            if device.isAutoFocusRangeRestrictionSupported { device.autoFocusRangeRestriction = .near }
            device.unlockForConfiguration()
        }
        session.startRunning()
        DispatchQueue.main.async { self.state = .scanning }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard !busy, Date().timeIntervalSince(lastFrame) > 0.25,
              let pixels = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        busy = true
        lastFrame = Date()
        let request = VNRecognizeTextRequest { [weak self] request, _ in
            let text = (request.results as? [VNRecognizedTextObservation])?
                .compactMap { $0.topCandidates(1).first?.string } ?? []
            self?.handle(text)
            self?.busy = false
        }
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        request.recognitionLanguages = ["en-US"]
        // The MRZ sits along the bottom of the photo page; the buffer is landscape.
        request.regionOfInterest = CGRect(x: 0, y: 0, width: 1, height: 1)
        try? VNImageRequestHandler(cvPixelBuffer: pixels, orientation: .right).perform([request])
    }

    private func handle(_ raw: [String]) {
        let lines = raw.map(MRZText.clean).filter { $0.count >= 28 && $0.filter { $0 == "<" }.count >= 2 }
        let match = MRZText.key(in: lines)
        DispatchQueue.main.async {
            guard self.state != .found else { return }
            self.lines = Array(lines.prefix(3))
            self.checks = match?.checks ?? [false, false, false]
            guard let key = match?.key, match?.checks.allSatisfy({ $0 }) == true else {
                self.candidate = nil
                return
            }
            if key == self.candidate {
                self.found = key
                self.record = match?.record
                self.state = .found
                self.stop()
            } else {
                self.candidate = key
            }
        }
    }
}

/// MRZ text from OCR to a key.
enum MRZText {
    /// Upper-case, filler normalised, anything outside the MRZ alphabet dropped.
    static func clean(_ text: String) -> String {
        text.uppercased()
            .replacingOccurrences(of: "«", with: "<<")
            .replacingOccurrences(of: "‹", with: "<")
            .filter { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "<") }
    }

    /// OCR confuses letters and digits; in a digits-only field the letter is wrong.
    private static func digits(_ text: Substring) -> String {
        let fixes: [Character: Character] = ["O": "0", "Q": "0", "D": "0", "U": "0", "I": "1", "L": "1", "Z": "2", "S": "5", "B": "8", "G": "6", "T": "7"]
        return String(text.map { fixes[$0] ?? $0 })
    }

    private static func slice(_ s: String, _ range: Range<Int>) -> Substring {
        let start = s.index(s.startIndex, offsetBy: range.lowerBound)
        let end = s.index(s.startIndex, offsetBy: range.upperBound)
        return s[start..<end]
    }

    struct Match {
        var key: DocumentKey
        var checks: [Bool]
        var record: MRZRecord?
    }

    static func key(in lines: [String]) -> Match? {
        // TD3 (passports): the second 44-character line carries all three fields.
        for (index, line) in lines.enumerated() where (43...45).contains(line.count) {
            let l = String(line.prefix(44)).padding(toLength: 44, withPad: "<", startingAt: 0)
            let doc = String(slice(l, 0..<9))
            let docCheck = digits(slice(l, 9..<10))
            let dob = digits(slice(l, 13..<19)), dobCheck = digits(slice(l, 19..<20))
            let doe = digits(slice(l, 21..<27)), doeCheck = digits(slice(l, 27..<28))
            guard let match = verify(doc: doc, docCheck: docCheck, dob: dob, dobCheck: dobCheck, doe: doe, doeCheck: doeCheck) else { continue }
            let first = lines.indices.contains(index - 1) ? lines[index - 1] : nil
            let record = first.flatMap { line1 -> MRZRecord? in
                guard line1.count == 44 else { return nil }
                let fixed = String(l.prefix(13)) + dob + dobCheck + String(slice(l, 20..<21)) + doe + doeCheck + String(slice(l, 28..<44))
                return PassportCore.parseMRZ(line1 + fixed)
            }
            return Match(key: match.key, checks: match.checks, record: record)
        }
        // TD1 (ID cards): number on line 1, dates on line 2.
        for (index, line) in lines.enumerated() where line.count == 30 && lines.indices.contains(index + 1) {
            let l1 = line, l2 = lines[index + 1]
            guard l2.count == 30, "IAC".contains(l1.first ?? " ") else { continue }
            let doc = String(slice(l1, 5..<14)), docCheck = digits(slice(l1, 14..<15))
            let dob = digits(slice(l2, 0..<6)), dobCheck = digits(slice(l2, 6..<7))
            let doe = digits(slice(l2, 8..<14)), doeCheck = digits(slice(l2, 14..<15))
            guard let match = verify(doc: doc, docCheck: docCheck, dob: dob, dobCheck: dobCheck, doe: doe, doeCheck: doeCheck) else { continue }
            let record = lines.indices.contains(index + 2) ? PassportCore.parseMRZ(l1 + l2 + lines[index + 2]) : nil
            return Match(key: match.key, checks: match.checks, record: record)
        }
        return nil
    }

    private static func verify(doc: String, docCheck: String, dob: String, dobCheck: String, doe: String, doeCheck: String) -> Match? {
        let key = DocumentKey(
            documentNumber: doc.trimmingCharacters(in: CharacterSet(charactersIn: "<")),
            dateOfBirth: dob,
            dateOfExpiry: doe
        )
        guard !key.documentNumber.isEmpty else { return nil }
        // Check digits are computed over the full 9-character field, filler included.
        let info = PassportCore.keyInfo(DocumentKey(documentNumber: doc, dateOfBirth: dob, dateOfExpiry: doe))
        guard info.ok, let digits = info.checkDigits, digits.count == 3 else { return nil }
        return Match(key: key, checks: [digits[0] == docCheck, digits[1] == dobCheck, digits[2] == doeCheck])
    }
}

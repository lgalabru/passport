import Foundation
import PassportFFI

/// Transport error codes of `PassportHost.transceive`.
enum TransceiveCode: Int32, Error {
    case timeout = 1
    case protocolError = 2
    case notPresent = 3
    case unsupported = 4
    case io = 5
}

/// Owns the Swift side of one `PassportHost`: the radio, progress, logs and
/// the file sink. The Rust reader calls back into it from the worker thread.
final class HostBridge {
    /// Radio exchange; called on the reader's worker thread and may block.
    var transceive: (Data) -> Result<Data, TransceiveCode> = { _ in .failure(.notPresent) }
    var onEvent: (ReaderEvent) -> Void = { _ in }
    var onLog: (LogLine) -> Void = { _ in }
    /// Called as a data group streams in, with everything received so far.
    var onStream: (_ name: String, _ data: Data) -> Void = { _, _ in }
    /// 0 = ISO 14443-4A, 1 = 14443-4B.
    var protocolCode: UInt8 = 0
    /// Whether the current read got past BAC; maintained by the reader.
    var authenticated = false

    let directory: URL
    private var handle: FileHandle?
    private var streamName = ""
    private var streamed = Data()
    private var lastStreamed = 0

    init(directory: URL) {
        self.directory = directory
    }

    /// A `PassportHost` pointing at this bridge. Valid while the bridge lives.
    func makeHost() -> PassportHost {
        var host = PassportHost()
        host.ctx = Unmanaged.passUnretained(self).toOpaque()
        host.protocol = protocolCode
        host.transceive = { ctx, tx, txLen, rx, rxCapacity, rxLen in
            let bridge = HostBridge.from(ctx)
            let command = Data(bytes: tx!, count: txLen)
            switch bridge.transceive(command) {
            case .success(let response):
                guard response.count <= rxCapacity else { return TransceiveCode.protocolError.rawValue }
                response.copyBytes(to: rx!, count: response.count)
                rxLen!.pointee = response.count
                return 0
            case .failure(let code):
                return code.rawValue
            }
        }
        host.event = { ctx, json in
            let bridge = HostBridge.from(ctx)
            if let event = PassportCore.decodeEvent(String(cString: json!)) {
                bridge.onEvent(event)
            }
        }
        host.log = { ctx, level, line in
            HostBridge.from(ctx).onLog(LogLine(level: LogLine.Level(rawValue: level) ?? .debug, text: String(cString: line!)))
        }
        host.sink_open = { ctx, name in
            HostBridge.from(ctx).open(String(cString: name!)) ? 0 : 1
        }
        host.sink_write = { ctx, data, len in
            HostBridge.from(ctx).write(Data(bytes: data!, count: len)) ? 0 : 1
        }
        host.sink_close = { ctx in
            HostBridge.from(ctx).close() ? 0 : 1
        }
        return host
    }

    private static func from(_ ctx: UnsafeMutableRawPointer?) -> HostBridge {
        Unmanaged<HostBridge>.fromOpaque(ctx!).takeUnretainedValue()
    }

    // MARK: Sink

    private func open(_ name: String) -> Bool {
        // The core sanitises the name; refuse anything path-like anyway.
        guard !name.contains("/"), !name.hasPrefix(".") else { return false }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(name)
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.protectionKey: FileProtectionType.complete]),
              let handle = try? FileHandle(forWritingTo: url) else { return false }
        self.handle = handle
        streamName = name
        streamed = Data()
        lastStreamed = 0
        return true
    }

    private func write(_ data: Data) -> Bool {
        guard let handle else { return false }
        do {
            try handle.write(contentsOf: data)
        } catch {
            return false
        }
        streamed.append(data)
        // Repainting a partial image on every 32-byte chunk is wasted work.
        if streamed.count - lastStreamed >= 768 {
            lastStreamed = streamed.count
            onStream(streamName, streamed)
        }
        return true
    }

    private func close() -> Bool {
        defer { handle = nil }
        onStream(streamName, streamed)
        do {
            try handle?.close()
            return true
        } catch {
            return false
        }
    }
}

struct LogLine: Identifiable, Equatable, Sendable {
    enum Level: UInt8, Sendable {
        case error = 0, warn, info, debug, txrx
    }

    let id = UUID()
    var level: Level
    var text: String
    var time = Date()
}

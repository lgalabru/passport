import AVFoundation
import SwiftUI

/// Adding a passport, as a sheet: why, scan, chip, done.
struct SetupFlow: View {
    @Environment(AppModel.self) private var model
    var setup: Setup

    var body: some View {
        NavigationStack {
            Group {
                switch setup.step {
                case .intro: SetupIntro(setup: setup)
                case .scan: ScanStep(setup: setup)
                case .manual: ManualStep(setup: setup)
                case .reading: ReadingStep(setup: setup)
                case .done: DoneStep()
                }
            }
            .animation(.default, value: setup.step)
            .toolbar {
                if setup.step != .done {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") {
                            model.cancelRead()
                            model.setup = nil
                        }
                    }
                }
            }
        }
        .interactiveDismissDisabled(setup.step == .reading)
    }
}

private struct SetupIntro: View {
    @Environment(AppModel.self) private var model
    var setup: Setup

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 28) {
                    Image(systemName: "person.text.rectangle")
                        .font(.system(size: 56, weight: .light))
                        .foregroundStyle(.tint)
                        .symbolRenderingMode(.hierarchical)
                        .padding(.top, 24)
                    Text("Add Passport")
                        .font(.largeTitle.bold())
                    VStack(alignment: .leading, spacing: 22) {
                        Feature(symbol: "text.viewfinder", title: "Scan the photo page",
                                text: "The two lines of letters at the bottom unlock the chip inside your passport.")
                        Feature(symbol: "wave.3.right", title: "Hold iPhone to your passport",
                                text: "The chip holds your photo and details, signed by the country that issued it. Passport checks that signature and that the chip is the original.")
                        Feature(symbol: "lock.shield", title: "Share answers, not your passport",
                                text: "When a website asks if you're over 18, it gets a mathematical proof of “yes”, and nothing else.")
                    }
                    .padding(.horizontal, 8)
                }
                .padding(.horizontal, 24)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            VStack(spacing: 12) {
                Button {
                    setup.step = .scan
                } label: {
                    Text("Continue").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                Button("Enter Details Manually") { setup.step = .manual }
                    .controlSize(.large)
            }
            .padding(24)
            .frame(maxWidth: 520)
        }
        .task {
            // The simulator has no camera: the demo goes straight to the chip.
            guard AppModel.demo else { return }
            try? await Task.sleep(for: .seconds(3))
            if setup.step == .intro { model.addSample() }
        }
    }
}

private struct Feature: View {
    var symbol: String
    var title: String
    var text: String

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(.tint)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                Text(text).font(.subheadline).foregroundStyle(.secondary)
            }
        }
    }
}

/// Camera on the photo page; the key is taken once two frames agree.
private struct ScanStep: View {
    @Environment(AppModel.self) private var model
    var setup: Setup
    @State private var scanner = MRZScanner()

    var body: some View {
        ZStack {
            if case .unavailable(let reason) = scanner.state {
                ContentUnavailableView {
                    Label("Camera Unavailable", systemImage: "camera")
                } description: {
                    Text(reason)
                } actions: {
                    Button("Enter Details Manually") { setup.step = .manual }
                        .buttonStyle(.borderedProminent)
                    if !model.nfcAvailable {
                        Button("Use Sample Passport") { model.addSample() }
                    }
                }
            } else {
                CameraPreview(session: scanner.session)
                    .ignoresSafeArea()
                guide
            }
        }
        .navigationTitle("Scan Photo Page")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .onAppear { scanner.start() }
        .onDisappear { scanner.stop() }
        .sensoryFeedback(.success, trigger: scanner.found)
        .onChange(of: scanner.found) { _, key in
            if let key { model.read(key, into: setup) }
        }
    }

    private var guide: some View {
        GeometryReader { proxy in
            let width = min(proxy.size.width - 48, 480)
            VStack(spacing: 16) {
                Spacer()
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(.white, lineWidth: 3)
                    .frame(width: width, height: width / 1.42)
                    .overlay(alignment: .bottom) {
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(.white.opacity(0.18))
                            .frame(height: width / 1.42 * 0.22)
                            .padding(10)
                    }
                Text("Fit the photo page in the frame, with the two lines of letters at the bottom.")
                    .font(.callout)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(.ultraThinMaterial, in: .rect(cornerRadius: 12, style: .continuous))
                    .frame(width: width)
                Spacer()
                Button("Enter Details Manually") { setup.step = .manual }
                    .buttonStyle(.bordered)
                    .tint(.white)
                    .padding(.bottom, 24)
            }
            .frame(maxWidth: .infinity)
        }
    }
}

/// The three fields, typed.
private struct ManualStep: View {
    @Environment(AppModel.self) private var model
    var setup: Setup
    @State private var number = ""
    @State private var birth = Calendar.current.date(byAdding: .year, value: -30, to: Date()) ?? Date()
    @State private var expiry = Calendar.current.date(byAdding: .year, value: 5, to: Date()) ?? Date()
    @FocusState private var focused: Bool

    private var key: DocumentKey {
        DocumentKey(documentNumber: number, dateOfBirth: MRZFormat.yymmdd(birth), dateOfExpiry: MRZFormat.yymmdd(expiry))
    }

    var body: some View {
        Form {
            Section {
                TextField("Document Number", text: $number)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .keyboardType(.asciiCapable)
                    .focused($focused)
                DatePicker("Date of Birth", selection: $birth, in: ...Date(), displayedComponents: .date)
                DatePicker("Expiry Date", selection: $expiry, displayedComponents: .date)
            } footer: {
                Text("As printed on the photo page. Passport uses them only to unlock the chip; they stay on this iPhone.")
            }
        }
        .navigationTitle("Passport Details")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Next") { model.read(key, into: setup) }
                    .disabled(!PassportCore.keyInfo(key).ok)
            }
        }
        .onAppear {
            if let key = setup.key ?? model.identity?.key {
                number = key.documentNumber
                birth = MRZFormat.date(key.dateOfBirth, birth: true) ?? birth
                expiry = MRZFormat.date(key.dateOfExpiry, birth: false) ?? expiry
            }
            focused = number.isEmpty
        }
    }
}

/// The chip read. CoreNFC shows its own sheet on a phone; this page mirrors
/// the progress so it reads well behind it, and on the simulator.
private struct ReadingStep: View {
    @Environment(AppModel.self) private var model
    var setup: Setup

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            Image(systemName: failed ? "exclamationmark.circle" : "wave.3.right.circle")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(failed ? AnyShapeStyle(.orange) : AnyShapeStyle(.tint))
                .symbolEffect(.variableColor.iterative, isActive: !failed)
                .contentTransition(.symbolEffect(.replace))
                .padding(.bottom, 24)
            Text(failed ? "Couldn't Read Passport" : "Hold iPhone to Your Passport")
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            Text(subtitle)
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 8)
                .padding(.horizontal, 32)
            if let progress = setup.progress, !failed {
                ProgressView(value: progress.overallFraction)
                    .frame(maxWidth: 260)
                    .padding(.top, 28)
                    .animation(.default, value: progress.overallFraction)
            }
            Spacer()
            if failed {
                VStack(spacing: 12) {
                    Button {
                        if let key = setup.key { model.read(key, into: setup, sample: setup.progress?.demo ?? false) }
                    } label: {
                        Text("Try Again").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    Button("Edit Details") { setup.step = .manual }
                        .controlSize(.large)
                }
                .padding(24)
                .frame(maxWidth: 440)
            }
        }
        .frame(maxWidth: .infinity)
        .navigationBarBackButtonHidden()
        .sensoryFeedback(.error, trigger: failed)
    }

    private var failed: Bool {
        if setup.error != nil { return true }
        if case .failed = setup.progress?.status { return true }
        return setup.progress?.status == .cancelled
    }

    private var subtitle: String {
        if let error = setup.error { return error }
        guard let progress = setup.progress else { return "" }
        switch progress.status {
        case .failed(let failure): return failure.message
        case .cancelled: return "The read was cancelled."
        default: break
        }
        if progress.demo, progress.stage == .waiting { return "Reading the sample passport." }
        switch progress.stage {
        case .waiting: return "Open your passport to the photo page and place the top of your iPhone on it."
        case .detected: return "Unlocking the chip…"
        case .authenticated, .reading:
            return progress.current == .dg(2) ? "Reading your photo. Keep still." : "Reading your details…"
        case .done: return "Done"
        }
    }
}

private struct DoneStep: View {
    @Environment(AppModel.self) private var model
    @State private var appeared = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            if let identity = model.identity {
                DataPage(identity: identity, portrait: model.portrait, masked: !model.showsPrivateDetails)
                    .padding(.horizontal, 12)
                    .paperPanel()
                    .frame(maxWidth: 360)
                    .padding(.horizontal, 32)
                    .scaleEffect(appeared ? 1 : 0.92)
                    .opacity(appeared ? 1 : 0)
            }
            Label("Passport Added", systemImage: "checkmark.circle.fill")
                .font(.title2.bold())
                .symbolRenderingMode(.multicolor)
                .padding(.top, 32)
            Text(model.session == nil
                 ? "Websites and apps can now ask Passport to prove things about you."
                 : "You can now answer \(model.session?.request?.displayName ?? "the request").")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 8)
                .padding(.horizontal, 32)
            Spacer()
            Button {
                model.finishSetup()
            } label: {
                Text("Done").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(24)
            .frame(maxWidth: 440)
        }
        .navigationBarBackButtonHidden()
        .sensoryFeedback(.success, trigger: appeared)
        .onAppear {
            withAnimation(.spring(duration: 0.5, bounce: 0.3)) { appeared = true }
        }
        .task {
            guard AppModel.demo else { return }
            try? await Task.sleep(for: .seconds(3.5))
            model.finishSetup()
        }
    }
}

struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    final class PreviewView: UIView {
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var preview: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.preview.session = session
        view.preview.videoGravity = .resizeAspectFill
        return view
    }

    func updateUIView(_ uiView: PreviewView, context: Context) {}
}

import SwiftUI

/// The Home section saying what backs this document's proofs, with the way
/// forward: enroll, or why it cannot.
struct VerificationSection: View {
    @Environment(AppModel.self) private var model
    var identity: Identity
    @State private var showsCompatibility = false

    var body: some View {
        Section {
            if let onChain = identity.onChain {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Verified passport")
                        Text("Enrolled in the registry on \(onChain.enrolledAt.formatted(date: .abbreviated, time: .omitted))")
                            .font(.footnote)
                            .foregroundStyle(Paper.faded)
                    }
                } icon: {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                }
            } else if identity.compatibility?.enrollable == true {
                Button {
                    model.enrollOnChain()
                } label: {
                    Label("Verify Passport", systemImage: "checkmark.seal")
                }
                .disabled(model.enrollmentBlocker != nil)
            } else {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Not verified")
                        Text(identity.compatibility == nil ? "Read your passport again to check it" : "This passport cannot be verified yet")
                            .font(.footnote)
                            .foregroundStyle(Paper.faded)
                    }
                } icon: {
                    Image(systemName: "seal").foregroundStyle(Paper.faded)
                }
            }
            if identity.compatibility != nil {
                Button("Compatibility") { showsCompatibility = true }
            }
        } header: {
            PaperHeading("Verification")
        } footer: {
            PaperFootnote(footer)
        }
        .paperRows()
        .sheet(isPresented: $showsCompatibility) {
            if let compatibility = identity.compatibility {
                NavigationStack { CompatibilityView(compatibility: compatibility) }
            }
        }
        .sheet(isPresented: Binding(
            get: { model.enrollment != nil },
            set: { if !$0, model.enrollment?.isRunning != true { model.enrollment = nil } }
        )) {
            if let session = model.enrollment {
                EnrollmentSheet(session: session)
            }
        }
    }

    private var footer: String {
        if identity.onChain != nil {
            return "Proofs are checked against the passport registry on Solana, which admitted this passport after verifying its chip and its issuer's signature."
        }
        if let blocker = model.enrollmentBlocker, identity.compatibility?.enrollable == true {
            return "Until verified, proofs come from this iPhone alone and websites should not rely on them. \(blocker)"
        }
        return "Until verified, proofs come from this iPhone alone and websites should not rely on them. Verifying proves your passport and its chip are genuine, on this iPhone, and records only an anonymous commitment on Solana."
    }
}

/// Each check enrollment depends on, and its outcome.
struct CompatibilityView: View {
    @Environment(\.dismiss) private var dismiss
    var compatibility: Compatibility

    var body: some View {
        List {
            Section {
                ForEach(compatibility.checks) { check in
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Image(systemName: symbol(check.passed))
                            .foregroundStyle(color(check.passed))
                        VStack(alignment: .leading, spacing: 3) {
                            Text(check.label)
                            Text(check.detail)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            } footer: {
                Text(compatibility.enrollable
                     ? "This passport can be verified. Its issuer's signer must also be on the registry's list, which is checked when verifying."
                     : "Passport verifies RSA signatures and RSA chip keys for now; support for more passports is coming.")
            }
            Section("Document") {
                LabeledContent("Issuing State", value: compatibility.issuingState)
                if let signer = compatibility.documentSigner {
                    LabeledContent("Signer", value: signer)
                }
                LabeledContent("Chip Key", value: compatibility.chipKey ?? "None")
            }
        }
        .navigationTitle("Compatibility")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
        }
    }

    private func symbol(_ passed: Bool?) -> String {
        switch passed {
        case true?: "checkmark.circle.fill"
        case false?: "xmark.circle.fill"
        case nil: "minus.circle"
        }
    }

    private func color(_ passed: Bool?) -> Color {
        switch passed {
        case true?: .green
        case false?: .red
        case nil: .secondary
        }
    }
}

/// Verifying: download the circuit, prove on this iPhone, send.
struct EnrollmentSheet: View {
    @Environment(AppModel.self) private var model
    var session: EnrollmentSession

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: symbol)
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(failed ? AnyShapeStyle(.red) : AnyShapeStyle(.tint))
                .symbolRenderingMode(.hierarchical)
                .contentTransition(.symbolEffect(.replace))
            Text(title)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            Text(detail)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            if case .downloading(let fraction) = session.phase {
                ProgressView(value: fraction)
                    .padding(.horizontal, 48)
            } else if session.isRunning {
                ProgressView()
            }
            Spacer()
            if !session.isRunning {
                Button {
                    model.enrollment = nil
                } label: {
                    Text("Done").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(24)
                .frame(maxWidth: 440)
            }
        }
        .interactiveDismissDisabled(session.isRunning)
        .sensoryFeedback(.success, trigger: session.phase == .done)
    }

    private var failed: Bool {
        if case .failed = session.phase { return true }
        return false
    }

    private var symbol: String {
        switch session.phase {
        case .downloading: "arrow.down.circle"
        case .proving: "function"
        case .sending, .confirming: "paperplane"
        case .done: "checkmark.seal.fill"
        case .failed: "exclamationmark.triangle"
        }
    }

    private var title: String {
        switch session.phase {
        case .downloading: "Getting Ready"
        case .proving: "Proving Your Passport"
        case .sending: "Sending"
        case .confirming: "Recording"
        case .done: "Passport Verified"
        case .failed: "Couldn't Verify"
        }
    }

    private var detail: String {
        switch session.phase {
        case .downloading(let fraction):
            "Downloading the verifier, once (about 450 MB). \(Int(fraction * 100))%"
        case .proving:
            "This iPhone is proving that your passport was signed by its issuer and that its chip is genuine. Nothing about you leaves the device."
        case .sending:
            "Sending the proof to the registry."
        case .confirming:
            "Waiting for the registry to record it."
        case .done:
            "Websites can now rely on what Passport proves about you\(session.proofMillis.map { ". Proved in \(String(format: "%.1f", Double($0) / 1000)) s." } ?? ".")"
        case .failed(let message):
            message
        }
    }
}

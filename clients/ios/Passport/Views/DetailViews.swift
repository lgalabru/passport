import SwiftUI

/// Everything the chip said, the way Settings lays out details.
struct DocumentDetails: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let identity = model.identity {
            let r = identity.record
            List {
                Section {
                    HStack {
                        Spacer()
                        portrait
                        Spacer()
                    }
                    .listRowBackground(Color.clear)
                }
                Section("Personal") {
                    LabeledContent("Surname", value: r.surname.capitalized)
                    LabeledContent("Given Names", value: r.givenNames.capitalized)
                    LabeledContent("Date of Birth", value: MRZFormat.pretty(r.dateOfBirth, birth: true))
                    LabeledContent("Sex", value: sex(r.gender))
                    LabeledContent("Nationality", value: "\(Country.flag(r.nationality)) \(Country.name(r.nationality))")
                }
                Section("Document") {
                    LabeledContent("Type", value: r.documentCode.hasPrefix("P") ? "Passport" : "Identity Card")
                    LabeledContent("Number", value: r.documentNumber)
                    LabeledContent("Issued By", value: Country.name(r.issuingState))
                    LabeledContent("Expires") {
                        HStack(spacing: 6) {
                            Text(MRZFormat.pretty(r.dateOfExpiry, birth: false))
                            if MRZFormat.isExpired(r.dateOfExpiry) {
                                Text("Expired")
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(.orange.opacity(0.18), in: .capsule)
                                    .foregroundStyle(.orange)
                            }
                        }
                    }
                }
                Section {
                    LabeledContent("Read", value: identity.enrolledAt.formatted(date: .abbreviated, time: .shortened))
                    LabeledContent("Access", value: "Basic Access Control")
                    LabeledContent("Check Digits", value: r.failedChecks.isEmpty ? "Valid" : "Failed: \(r.failedChecks.joined(separator: ", "))")
                } header: {
                    Text("Chip")
                } footer: {
                    Text(identity.sample
                         ? "This is the ICAO sample passport, read from a chip built into Passport."
                         : "Read directly from the chip in your document over NFC.")
                }
                Section {
                    LabeledContent("Registry", value: identity.onChain == nil ? "On this iPhone" : "Solana")
                    if let onChain = identity.onChain {
                        LabeledContent("Program", value: String(onChain.programId.prefix(8)) + "…")
                        LabeledContent("Evidence", value: "Chip and issuer verified")
                    } else {
                        LabeledContent("Evidence", value: "None (development)")
                    }
                    LabeledContent("Proof System", value: "Groth16 · BN254")
                } header: {
                    Text("Proofs")
                } footer: {
                    Text(identity.onChain == nil
                         ? "Development: proofs are checked against a registry kept on this iPhone. Relying parties should not accept them as evidence. Verify your passport to enroll it in the registry."
                         : "Proofs are checked against the passport registry on Solana. Its keys come from a development setup until the trusted setup ceremony is done.")
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Document Details")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var portrait: some View {
        Group {
            if let image = model.portrait {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                Image(systemName: "person.crop.rectangle").font(.largeTitle).foregroundStyle(.secondary)
            }
        }
        .frame(width: 120, height: 150)
        .clipShape(.rect(cornerRadius: 14, style: .continuous))
        .accessibilityLabel("Photo from the chip")
    }

    private func sex(_ code: String) -> String {
        switch code {
        case "F": "Female"
        case "M": "Male"
        default: "Unspecified"
        }
    }
}

/// One past share: who, when, what.
struct PresentationDetail: View {
    var presentation: Presentation
    @State private var copied = false

    var body: some View {
        List {
            Section {
                VStack(spacing: 8) {
                    VerifierBadge(name: presentation.verifier, size: 56)
                    Text(presentation.verifier).font(.title3.bold())
                    Text(presentation.date.formatted(date: .long, time: .shortened))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }
            Section("Shared") {
                ForEach(presentation.shared, id: \.self) { item in
                    LabeledContent(item.label, value: item.display)
                }
            }
            Section {
                LabeledContent("Sent To", value: presentation.recipient)
                LabeledContent("Proved In", value: "\(presentation.millis) ms")
                Button(copied ? "Copied" : "Copy Proof", systemImage: copied ? "checkmark" : "doc.on.doc") {
                    UIPasteboard.general.string = presentation.token
                    copied = true
                }
            } footer: {
                Text("The proof is all \(presentation.verifier) received. It shows the answers above are true for a passport enrolled on this iPhone, without revealing which one.")
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Shared")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// The Duo's right-hand page before anything is selected.
struct PagePlaceholder: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ContentUnavailableView {
            Label(model.identity == nil ? "No Passport" : "No Requests", systemImage: "checkmark.shield")
        } description: {
            Text(model.identity == nil
                 ? "Add a passport to answer requests from websites and apps."
                 : "Requests from websites and apps open here.")
        }
    }
}

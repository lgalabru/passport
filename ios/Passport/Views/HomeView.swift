import SwiftUI

/// The first page: the document, and what has been shared from it.
struct HomeView: View {
    @Environment(AppModel.self) private var model
    /// On a two-page Duo layout, rows select into the other page instead of pushing.
    var spread = false
    @State private var confirmRemove = false

    /// Folded (or one screen, not unlocked): the card shows no personal details.
    private var masked: Bool { !model.showsPrivateDetails }

    var body: some View {
        Group {
            if let identity = model.identity {
                list(identity)
            } else {
                EmptyHome()
            }
        }
        .navigationTitle("Passport")
        .toolbar {
            if model.identity != nil {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Remove Passport", systemImage: "trash", role: .destructive) { confirmRemove = true }
                    } label: {
                        Image(systemName: "ellipsis")
                    }
                    .accessibilityLabel("More")
                }
            }
        }
        .confirmationDialog("Remove this passport?", isPresented: $confirmRemove, titleVisibility: .visible) {
            Button("Remove Passport", role: .destructive) { model.removeDocument() }
        } message: {
            Text("Its details and your sharing history are deleted from this iPhone. You can add it again at any time.")
        }
    }

    private func list(_ identity: Identity) -> some View {
        List {
            Section {
                PassportCard(identity: identity, portrait: model.portrait, masked: masked)
                    .contentShape(.rect)
                    .onTapGesture { if masked { Task { await model.reveal() } } }
                    .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 8, trailing: 0))
                    .listRowBackground(Color.clear)
                    .animation(.smooth, value: masked)
            } footer: {
                if masked {
                    Label("Tap to show your details", systemImage: "lock")
                        .font(.footnote)
                        .frame(maxWidth: .infinity)
                }
            }

            if !masked {
                Section {
                    row(.document) {
                        Label("Document Details", systemImage: "person.text.rectangle")
                    }
                } footer: {
                    Text("Read from the chip in your \(identity.record.documentCode.hasPrefix("P") ? "passport" : "card") on \(identity.enrolledAt.formatted(date: .abbreviated, time: .omitted)).")
                }
            }

            Section {
                if model.history.isEmpty {
                    Text("Nothing shared yet")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.history) { presentation in
                        row(.presentation(presentation.id)) {
                            PresentationRow(presentation: presentation)
                        }
                    }
                }
            } header: {
                Text("Shared")
            } footer: {
                Text("When a website or app asks you to prove something, like being over 18, Passport answers with a proof. It never sends your passport.")
            }
        }
        .listStyle(.insetGrouped)
    }

    @ViewBuilder
    private func row<Label: View>(_ selection: AppModel.Selection, @ViewBuilder label: () -> Label) -> some View {
        if spread {
            Button {
                model.selection = selection
            } label: {
                HStack {
                    label()
                    Spacer()
                    Image(systemName: "chevron.forward")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .listRowBackground(model.selection == selection ? Color(.systemFill) : nil)
        } else {
            NavigationLink(value: selection) { label() }
        }
    }
}

struct PresentationRow: View {
    var presentation: Presentation

    var body: some View {
        HStack(spacing: 12) {
            VerifierBadge(name: presentation.verifier, size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(presentation.verifier)
                    .font(.body.weight(.medium))
                Text(presentation.shared.map(\.summary).joined(separator: " · "))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            Text(presentation.date.formatted(.relative(presentation: .named)))
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

/// A relying party's initial in a tinted circle, or its logo.
struct VerifierBadge: View {
    var name: String
    var logo: URL? = nil
    var size: CGFloat

    var body: some View {
        ZStack {
            Circle().fill(Color.accentColor.gradient)
            Text(String(name.prefix(1)).uppercased())
                .font(.system(size: size * 0.44, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
            if let logo {
                AsyncImage(url: logo) { image in
                    image.resizable().scaledToFill()
                } placeholder: {
                    Color.clear
                }
                .clipShape(Circle())
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// Before any document is added.
private struct EmptyHome: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            Image(systemName: "person.text.rectangle")
                .font(.system(size: 64, weight: .light))
                .foregroundStyle(.tint)
                .symbolRenderingMode(.hierarchical)
                .padding(.bottom, 20)
            Text("Add Your Passport")
                .font(.title.bold())
            Text("Prove things about yourself, like being over 18, without showing your passport to anyone.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 8)
                .padding(.horizontal, 32)
            Spacer()
            VStack(spacing: 12) {
                Button {
                    model.beginSetup()
                } label: {
                    Text("Add Passport").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                Button("Use Sample Passport") { model.addSample() }
                    .controlSize(.large)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 12)
            .frame(maxWidth: 440)
        }
        .frame(maxWidth: .infinity)
    }
}

extension Presentation.Shared {
    /// `18+`, `Under 21`, `Utopia`: one shared answer in a few characters.
    var summary: String {
        if label.hasPrefix("You are "), label.hasSuffix(" or older") {
            let age = label.dropFirst("You are ".count).dropLast(" or older".count)
            return display == "Yes" ? "\(age)+" : "Under \(age)"
        }
        if label == "Your document has not expired" { return display == "Yes" ? "Valid document" : "Expired document" }
        if display.count == 3, display.allSatisfy(\.isUppercase) { return Country.name(display) }
        return display
    }
}

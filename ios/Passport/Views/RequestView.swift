import LocalAuthentication
import SwiftUI

/// A relying party asks; the person sees exactly what would be shared, then
/// shares or declines. A sheet on one screen; the right-hand page on a Duo.
struct RequestView: View {
    @Environment(AppModel.self) private var model
    var session: RequestSession
    /// Shown on the right-hand page of an unfolded Duo rather than in a sheet.
    var onPage = false

    var body: some View {
        Group {
            switch session.phase {
            case .loading:
                ProgressView("Loading request…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .failed(let message):
                ContentUnavailableView {
                    Label("Can't Answer This Request", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(message)
                } actions: {
                    Button("Close") { model.dismiss(session) }
                        .buttonStyle(.bordered)
                }
            case .done:
                Finished(session: session, onPage: onPage)
            default:
                if let request = session.request {
                    Review(session: session, request: request, onPage: onPage)
                }
            }
        }
        .animation(.default, value: session.phase)
    }
}

private struct Review: View {
    @Environment(AppModel.self) private var model
    var session: RequestSession
    var request: VerificationRequest
    var onPage: Bool

    private var busy: Bool { session.phase == .proving || session.phase == .sending }

    /// The glyph of whatever unlocks Share on this iPhone.
    private var biometrySymbol: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .touchID: return "touchid"
        case .opticID: return "opticid"
        default: return "faceid"
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 20) {
                    header
                    if model.identity == nil {
                        noPassport
                    } else {
                        claims
                        unmet
                        privacy
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 28)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            if model.identity != nil {
                actions
            }
        }
        .background(Color(.systemGroupedBackground))
        .task(id: onPage) {
            // Demo recording: approve once the Duo is open on the request.
            guard AppModel.demo, onPage, model.identity != nil else { return }
            try? await Task.sleep(for: .seconds(2.5))
            if session.phase == .review { await model.share(session) }
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            VerifierBadge(name: request.displayName, logo: request.logoUri.flatMap(URL.init(string:)), size: 64)
            Text(request.displayName)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            Text(request.purpose ?? "wants you to verify")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Label(request.recipient, systemImage: request.responseUri.hasPrefix("https://") ? "lock.fill" : "exclamationmark.triangle")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .labelStyle(.titleAndIcon)
        }
    }

    private var claims: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                HStack(spacing: 14) {
                    Image(systemName: row.symbol)
                        .font(.body)
                        .foregroundStyle(.tint)
                        .frame(width: 26)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.label)
                        if row.discloses {
                            Text("Shared with \(request.displayName)")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer(minLength: 12)
                    Text(row.value)
                        .font(.body.weight(.semibold))
                        .foregroundStyle(row.value == "No" ? Color.orange : Color.primary)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 13)
                if index < rows.count - 1 {
                    Divider().padding(.leading, 56)
                }
            }
        }
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 14, style: .continuous))
    }

    @ViewBuilder
    private var unmet: some View {
        if rows.contains(where: { $0.value == "No" }) {
            Text("Your passport doesn't meet every condition. \(request.displayName) will see “No” where it doesn't.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.top, -12)
        }
    }

    private struct Row {
        var label: String
        var value: String
        var discloses: Bool
        var symbol: String
    }

    private var rows: [Row] {
        request.claims.enumerated().map { index, claim in
            let preview = session.preview.indices.contains(index) ? session.preview[index] : nil
            return Row(label: claim.label, value: preview.map(display) ?? "—", discloses: claim.discloses, symbol: symbol(claim.path))
        }
    }

    private func display(_ preview: ClaimPreview) -> String {
        // Country codes read better as names.
        if preview.display.count == 3, preview.display.allSatisfy(\.isUppercase), preview.label.contains("ation") || preview.label.contains("country") {
            return "\(Country.flag(preview.display)) \(Country.name(preview.display))"
        }
        if preview.label == "Your date of birth", let date = ISO8601DateFormatter.day.date(from: preview.display) {
            return date.formatted(date: .abbreviated, time: .omitted)
        }
        return preview.display
    }

    private func symbol(_ path: [String]) -> String {
        switch path.first {
        case "age_equal_or_over", "age_in_years": "person.badge.clock"
        case "nationalities": "flag"
        case "issuing_country": "building.columns"
        case "expiry_date_valid": "calendar.badge.checkmark"
        case "birthdate": "birthday.cake"
        default: "checkmark.seal"
        }
    }

    private var privacy: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "hand.raised.fill")
                .foregroundStyle(.tint)
            Text("\(request.displayName) receives a zero-knowledge proof of \(rows.count == 1 ? "this answer" : "these answers"). Your name, photo and document number stay on this iPhone.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 4)
    }

    private var noPassport: some View {
        VStack(spacing: 14) {
            Text("Add your passport to answer this request.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Add Passport") { model.beginSetup() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            Button("Not Now") { model.decline(session) }
        }
        .padding(.top, 12)
    }

    private var actions: some View {
        VStack(spacing: 10) {
            Button {
                Task { await model.share(session) }
            } label: {
                HStack(spacing: 8) {
                    if busy {
                        ProgressView().tint(.white)
                        Text(session.phase == .proving ? "Creating Proof…" : "Sending…")
                    } else {
                        Image(systemName: biometrySymbol)
                        Text("Share")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(busy || !model.proverReady)
            Button("Don't Share") { model.decline(session) }
                .controlSize(.large)
                .disabled(busy)
            if let error = model.proverError {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
        .frame(maxWidth: 520)
        .frame(maxWidth: .infinity)
        .background(.bar)
    }
}

private struct Finished: View {
    @Environment(AppModel.self) private var model
    var session: RequestSession
    var onPage: Bool
    @State private var shown = false

    private var redirect: URL? {
        if case .done(let url) = session.phase { return url }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 72))
                .foregroundStyle(.green)
                .symbolEffect(.bounce, value: shown)
            Text("Shared")
                .font(.title.bold())
                .padding(.top, 16)
            Text("\(session.request?.displayName ?? "The website") has your proof.")
                .foregroundStyle(.secondary)
                .padding(.top, 6)
            Spacer()
            Button {
                model.dismiss(session)
            } label: {
                Text(redirect == nil ? "Done" : "Return to \(session.request?.displayName ?? "Website")")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(20)
            .frame(maxWidth: 520)
        }
        .frame(maxWidth: .infinity)
        .background(Color(.systemGroupedBackground))
        .sensoryFeedback(.success, trigger: shown)
        .onAppear { shown = true }
        .task(id: onPage) {
            // Demo recording: once folded again, return to the home screen.
            guard AppModel.demo, !onPage else { return }
            try? await Task.sleep(for: .seconds(3))
            model.dismiss(session)
        }
    }
}

extension ISO8601DateFormatter {
    static let day: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        return formatter
    }()
}

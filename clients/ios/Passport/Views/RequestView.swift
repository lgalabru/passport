import LocalAuthentication
import SwiftUI

/// Requests from relying parties, each one card: who asks, what the passport
/// would attest, and the two answers, Share or Don't Share. The right-hand
/// page of an unfolded Duo lists them; on one screen a card comes as a sheet.
struct RequestsPage: View {
    var sessions: [RequestSession]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PaperHeading(sessions.count == 1 ? "Request" : "Requests")
                    .padding(.leading, 6)
                ForEach(sessions) { session in
                    RequestCard(session: session, onPage: true)
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 24)
            .padding(.bottom, 32)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
        .toolbar(.hidden, for: .navigationBar)
    }
}

/// One request on one screen: a sheet shaped like a right-hand page.
struct RequestView: View {
    var session: RequestSession
    /// Shown on the right-hand page of an unfolded Duo rather than in a sheet.
    var onPage = false

    var body: some View {
        ScrollView {
            RequestCard(session: session, onPage: onPage)
                .padding(.horizontal, 20)
                .padding(.vertical, 28)
                .frame(maxWidth: 560)
                .frame(maxWidth: .infinity)
        }
        .background { if !onPage { PageBackground(side: .right) } }
        .scrollContentBackground(.hidden)
        .tint(Paper.gold)
        .foregroundStyle(Paper.ink)
    }
}

/// The card: a relying party's request, reviewed and answered in place.
struct RequestCard: View {
    @Environment(AppModel.self) private var model
    var session: RequestSession
    var onPage: Bool

    var body: some View {
        VStack(spacing: 0) {
            switch session.phase {
            case .loading:
                HStack(spacing: 12) {
                    ProgressView().tint(Paper.gold)
                    Text("Loading the request…").foregroundStyle(Paper.faded)
                }
                .padding(28)
            case .failed(let message):
                VStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 30, weight: .light))
                        .foregroundStyle(.orange)
                    Text("Can't Answer This Request").font(.engraved(.title3, weight: .bold))
                    Text(message).font(.footnote).foregroundStyle(Paper.faded).multilineTextAlignment(.center)
                    Button("Close") { model.dismiss(session) }
                        .buttonStyle(Flat(.decline))
                        .padding(.top, 4)
                }
                .padding(24)
            case .done:
                Finished(session: session, onPage: onPage)
            default:
                if let request = session.request {
                    Review(session: session, request: request, onPage: onPage)
                }
            }
        }
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .fill(Color.white.opacity(0.66))
                .shadow(color: Paper.ink.opacity(0.10), radius: 18, y: 8)
        )
        .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).strokeBorder(Paper.gold.opacity(0.5), lineWidth: 1))
        .animation(.default, value: session.phase)
    }
}

// MARK: - Review

private struct Review: View {
    @Environment(AppModel.self) private var model
    var session: RequestSession
    var request: VerificationRequest
    var onPage: Bool

    private var busy: Bool { session.phase == .proving || session.phase == .sending }
    private var secure: Bool { request.responseUri.hasPrefix("https://") }

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
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.top, 20)
                .padding(.bottom, 16)
            rule
            if model.identity == nil {
                noPassport
            } else {
                claims
                rule
                footer
                    .padding(.horizontal, 20)
                    .padding(.top, 14)
                actions
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                    .padding(.bottom, 20)
            }
        }
        .task(id: onPage) {
            // Demo recording: approve once the Duo is open on the request.
            guard AppModel.demo, onPage, model.identity != nil else { return }
            try? await Task.sleep(for: .seconds(2.5))
            if session.phase == .review { await model.share(session) }
        }
    }

    private var rule: some View {
        Rectangle().fill(Paper.gold.opacity(0.35)).frame(height: 0.5)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Seal(name: request.displayName, logo: request.logoUri.flatMap(URL.init(string:)))
            VStack(alignment: .leading, spacing: 3) {
                Text(request.displayName)
                    .font(.engraved(.title3, weight: .bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                if let name = request.clientName, name != request.displayName {
                    Text("Calls itself “\(name)”")
                        .font(.caption)
                        .foregroundStyle(Paper.faded)
                }
                Text(request.purpose ?? "asks your passport to attest")
                    .font(.subheadline)
                    .foregroundStyle(Paper.faded)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Image(systemName: secure ? "lock.fill" : "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(secure ? Paper.gold : .orange)
                .padding(7)
                .background(Circle().fill(Paper.gold.opacity(secure ? 0.14 : 0)).overlay(Circle().strokeBorder(Paper.gold.opacity(0.4), lineWidth: 0.5)))
                .accessibilityLabel(secure ? "Sent over HTTPS" : "Not sent over HTTPS")
        }
    }

    private var claims: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                HStack(spacing: 14) {
                    Image(systemName: row.symbol)
                        .font(.body)
                        .foregroundStyle(Paper.gold)
                        .frame(width: 26)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.label)
                        if row.discloses {
                            Text("Shared with \(request.displayName)")
                                .font(.caption)
                                .foregroundStyle(Paper.faded)
                        }
                    }
                    Spacer(minLength: 12)
                    Text(row.value)
                        .font(.engraved(.body))
                        .foregroundStyle(row.value == "No" ? Color.orange : Paper.ink)
                        .multilineTextAlignment(.trailing)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 13)
                if index < rows.count - 1 {
                    rule.padding(.leading, 60)
                }
            }
        }
    }

    @ViewBuilder
    private var footer: some View {
        if rows.contains(where: { $0.value == "No" }) {
            Text("Your passport doesn't meet every condition. \(request.displayName) will see “No” where it doesn't.")
                .font(.footnote)
                .foregroundStyle(.orange)
                .padding(.bottom, 8)
        }
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "hand.raised.fill")
                .font(.footnote)
                .foregroundStyle(Paper.gold)
                .padding(.top, 1)
            Text("\(request.displayName) receives a zero-knowledge proof of \(rows.count == 1 ? "this answer" : "these answers"). Your name, photo and document number stay on this iPhone.")
                .font(.footnote)
                .foregroundStyle(Paper.faded)
        }
    }

    private var actions: some View {
        VStack(spacing: 10) {
            HStack(spacing: 12) {
                Button {
                    model.decline(session)
                } label: {
                    Text("Don't Share")
                }
                .buttonStyle(Flat(.decline))
                .disabled(busy)
                Button {
                    Task { await model.share(session) }
                } label: {
                    HStack(spacing: 8) {
                        if busy {
                            ProgressView().tint(.white)
                            Text(session.phase == .proving ? "Proving…" : "Sending…")
                        } else {
                            Image(systemName: biometrySymbol)
                            Text("Share")
                        }
                    }
                }
                .buttonStyle(Flat(.accept))
                .disabled(busy || !model.proverReady)
            }
            if let error = model.proverError {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
        }
    }

    private var noPassport: some View {
        VStack(spacing: 14) {
            Text("Add your passport to answer this request.")
                .foregroundStyle(Paper.faded)
                .multilineTextAlignment(.center)
            HStack(spacing: 12) {
                Button("Not Now") { model.decline(session) }.buttonStyle(Flat(.decline))
                Button("Add Passport") { model.beginSetup() }.buttonStyle(Flat(.accept))
            }
        }
        .padding(20)
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
}

// MARK: - Finished

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
        VStack(spacing: 10) {
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 44))
                .foregroundStyle(Paper.gold)
                .symbolEffect(.bounce, value: shown)
                .padding(.top, 6)
            Text("Shared")
                .font(.engraved(.title2, weight: .bold))
            Text("\(session.request?.displayName ?? "The website") has your proof.")
                .font(.subheadline)
                .foregroundStyle(Paper.faded)
                .multilineTextAlignment(.center)
            Button {
                model.dismiss(session)
            } label: {
                Text(redirect == nil ? "Done" : "Return to \(session.request?.displayName ?? "Website")")
            }
            .buttonStyle(Flat(.accept))
            .padding(.top, 10)
        }
        .padding(24)
        .frame(maxWidth: .infinity)
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

// MARK: - Pieces

/// A relying party's initial in a navy seal, or its logo.
private struct Seal: View {
    var name: String
    var logo: URL?

    var body: some View {
        VerifierBadge(name: name, logo: logo, size: 46)
            .overlay(Circle().strokeBorder(Paper.gold.opacity(0.6), lineWidth: 1))
    }
}

/// The flat button of a call: green takes it, red declines.
struct Flat: ButtonStyle {
    enum Answer {
        case accept, decline

        var color: Color {
            switch self {
            case .accept: Color(red: 0.20, green: 0.70, blue: 0.36)
            case .decline: Color(red: 0.86, green: 0.24, blue: 0.22)
            }
        }
    }

    var answer: Answer
    @Environment(\.isEnabled) private var enabled

    init(_ answer: Answer) {
        self.answer = answer
    }

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 13)
            .background(Capsule().fill(answer.color))
            .opacity(enabled ? (configuration.isPressed ? 0.8 : 1) : 0.4)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.spring(duration: 0.2), value: configuration.isPressed)
    }
}

extension ISO8601DateFormatter {
    static let day: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        return formatter
    }()
}

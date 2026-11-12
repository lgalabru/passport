import SwiftUI

/// The closed passport: what a folded iPhone Duo shows until the holder opens
/// it, by unfolding the phone or tapping. Nothing about the document is on
/// it, as on a real cover; only what is waiting inside: the requests to
/// review, who asks and for what.
///
/// The artwork fills the screen's width, sitting on the bottom edge so the
/// embossed title clears the camera; above it the leather continues as the
/// artwork's own top band, mirrored.
struct CoverView: View {
    /// Requests waiting to be reviewed inside.
    var pending: [RequestSession] = []
    var onOpen: () -> Void

    /// The artwork's aspect ratio (width over height).
    private let aspect: CGFloat = 670 / 975

    var body: some View {
        GeometryReader { proxy in
            let width = proxy.size.width
            let height = proxy.size.height
            // The artwork, filling the width.
            let artHeight = width / aspect
            // Above it, its own top band (leather and waves, nothing embossed)
            // mirrored, and stretched when the gap is taller than it.
            let gap = max(0, height - artHeight)
            let band = 0.07 * artHeight
            let stretch = max(1, gap / band)
            ZStack(alignment: .bottom) {
                Paper.leather
                if gap > 0 {
                    Image("PassportCover")
                        .resizable()
                        .frame(width: width, height: artHeight * stretch)
                        .scaleEffect(x: 1, y: -1)
                        .offset(y: -artHeight)
                        .blur(radius: stretch > 1.5 ? 1 : 0)
                }
                Image("PassportCover")
                    .resizable()
                    .frame(width: width, height: artHeight)
            }
            .frame(width: width, height: height, alignment: .bottom)
            .clipped()
            .overlay(alignment: .bottom) {
                if !pending.isEmpty {
                    PendingRequests(pending: pending, onOpen: onOpen)
                        .padding(.horizontal, 20)
                        .padding(.bottom, max(proxy.safeAreaInsets.bottom, 16) + 18)
                }
            }
            .animation(.spring(duration: 0.4), value: pending.count)
        }
        .background(Paper.leather)
        .ignoresSafeArea()
        .statusBarHidden()
        .contentShape(Rectangle())
        .onTapGesture { onOpen() }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(pending.isEmpty ? "Passport, closed. Tap, or unfold the phone, to open it" : "Passport, closed. \(pending.count) request\(pending.count == 1 ? "" : "s") waiting")
    }
}

/// What waits inside: the requests to review, who asks and for what. Tapping
/// one opens the passport on it.
private struct PendingRequests: View {
    var pending: [RequestSession]
    var onOpen: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(pending.count == 1 ? "WAITING FOR YOU" : "\(pending.count) WAITING FOR YOU")
                .font(.system(.caption2, design: .serif).weight(.bold))
                .tracking(2)
                .foregroundStyle(Paper.gold.opacity(0.85))
                .padding(.horizontal, 16)
                .padding(.top, 12)
                .padding(.bottom, 8)
            ForEach(Array(pending.enumerated()), id: \.element.id) { index, session in
                if index > 0 {
                    Divider().overlay(Paper.gold.opacity(0.25)).padding(.leading, 62)
                }
                PendingRow(session: session)
                    .contentShape(Rectangle())
                    .onTapGesture { onOpen() }
            }
        }
        .padding(.bottom, 6)
        .background(.black.opacity(0.34), in: .rect(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(Paper.gold.opacity(0.5), lineWidth: 1))
        .shadow(color: .black.opacity(0.35), radius: 14, y: 6)
        .transition(.move(edge: .bottom).combined(with: .opacity))
        .accessibilityElement(children: .contain)
    }
}

/// One request: the relying party, and what it asks the passport to attest.
private struct PendingRow: View {
    var session: RequestSession

    private var name: String { session.request?.displayName ?? "A website" }

    /// `18+ · Nationality`: what is asked, in a few characters each.
    private var asks: String {
        guard let request = session.request else { return "Loading the request…" }
        let parts = request.claims.map(\.summary)
        return parts.isEmpty ? "wants you to verify" : parts.joined(separator: " · ")
    }

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle().fill(Paper.gold.opacity(0.18))
                Circle().strokeBorder(Paper.gold.opacity(0.7), lineWidth: 1)
                Text(String(name.prefix(1)).uppercased())
                    .font(.system(.body, design: .serif).weight(.bold))
                    .foregroundStyle(Paper.gold)
            }
            .frame(width: 36, height: 36)
            VStack(alignment: .leading, spacing: 3) {
                Text(name)
                    .font(.system(.subheadline, design: .serif).weight(.semibold))
                    .foregroundStyle(Color(red: 0.97, green: 0.93, blue: 0.82))
                    .lineLimit(1)
                Text(asks)
                    .font(.footnote)
                    .foregroundStyle(Paper.gold.opacity(0.85))
                    .lineLimit(2)
            }
            Spacer(minLength: 8)
            Image(systemName: "chevron.right")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(Paper.gold.opacity(0.7))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(name) asks: \(asks)")
        .accessibilityHint("Opens the passport on this request")
        .accessibilityAddTraits(.isButton)
    }
}

extension VerificationRequest.Claim {
    /// `18+`, `Nationality`, `Date of birth`: one asked claim in a few characters.
    var summary: String {
        if label.hasPrefix("You are "), label.hasSuffix(" or older") {
            return String(label.dropFirst("You are ".count).dropLast(" or older".count)) + "+"
        }
        if label == "Your document has not expired" { return "Valid document" }
        if label.hasPrefix("Your ") {
            let rest = label.dropFirst("Your ".count)
            return rest.prefix(1).uppercased() + rest.dropFirst()
        }
        return label
    }
}

#Preview("Closed") {
    CoverView {}
}

#Preview("A request waiting") {
    CoverView(pending: [RequestSession(url: URL(string: "openid4vp://")!)]) {}
}

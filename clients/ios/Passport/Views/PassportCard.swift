import SwiftUI

/// The enrolled document as a card, in the manner of a pass in Wallet.
struct PassportCard: View {
    var identity: Identity
    var portrait: UIImage?
    /// The folded, glanceable face: no name, photo or birth date, only the
    /// document's kind, issuer and the last characters of its number.
    var masked = false

    private var record: MRZRecord { identity.record }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(record.documentCode.hasPrefix("P") ? "PASSPORT" : "IDENTITY CARD")
                    .font(.caption.weight(.semibold))
                    .tracking(1.2)
                    .foregroundStyle(.white.opacity(0.75))
                Spacer()
                if identity.sample {
                    Text("SAMPLE")
                        .font(.caption2.weight(.bold))
                        .tracking(0.8)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(.white.opacity(0.18), in: .capsule)
                        .foregroundStyle(.white)
                }
                Text("\(Country.flag(record.issuingState)) \(record.issuingState)")
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.white.opacity(0.9))
            }
            Spacer(minLength: 12)
            if masked {
                maskedFace
            } else {
                fullFace
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .aspectRatio(1.586, contentMode: .fit)
        .background {
            ZStack {
                LinearGradient(
                    colors: [Color(red: 0.13, green: 0.22, blue: 0.40), Color(red: 0.05, green: 0.10, blue: 0.22)],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                )
                RadialGradient(colors: [.white.opacity(0.16), .clear], center: .topLeading, startRadius: 0, endRadius: 320)
            }
        }
        .clipShape(.rect(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(.white.opacity(0.12), lineWidth: 0.5))
        .shadow(color: .black.opacity(0.18), radius: 12, y: 6)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(masked ? "\(kind), ending \(lastCharacters)" : "\(record.givenNames) \(record.surname), \(Country.name(record.issuingState)) \(kind)")
    }

    private var kind: String { record.documentCode.hasPrefix("P") ? "passport" : "identity card" }

    private var lastCharacters: String { String(record.documentNumber.suffix(4)) }

    private var maskedFace: some View {
        HStack(alignment: .bottom) {
            VStack(alignment: .leading, spacing: 6) {
                Label(identity.verified ? "Verified passport" : "Read from chip",
                      systemImage: identity.verified ? "checkmark.seal.fill" : "wave.3.right")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.75))
                Text("•••• \(lastCharacters)")
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .foregroundStyle(.white)
            }
            Spacer()
            Image(systemName: "lock.fill")
                .font(.title3)
                .foregroundStyle(.white.opacity(0.5))
        }
    }

    private var fullFace: some View {
            HStack(alignment: .bottom, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(record.givenNames.capitalized)
                        .font(.title3.weight(.semibold))
                    Text(record.surname.capitalized)
                        .font(.title3.weight(.semibold))
                    Text("Born \(MRZFormat.pretty(record.dateOfBirth, birth: true))")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.7))
                        .padding(.top, 2)
                }
                .foregroundStyle(.white)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                Spacer()
                photo
            }
    }

    private var photo: some View {
        Group {
            if let portrait {
                Image(uiImage: portrait).resizable().scaledToFill()
            } else {
                Image(systemName: "person.fill")
                    .font(.title)
                    .foregroundStyle(.white.opacity(0.5))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(.white.opacity(0.1))
            }
        }
        .frame(width: 62, height: 78)
        .clipShape(.rect(cornerRadius: 8, style: .continuous))
    }
}

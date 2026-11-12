import SwiftUI

/// The biographical data page, printed on the page itself: the portrait, the
/// fields in the order a passport lays them out, and the machine-readable
/// zone along the bottom.
struct DataPage: View {
    var identity: Identity
    var portrait: UIImage?
    /// The folded, glanceable face: the document's kind, issuer and the last
    /// characters of its number stay; everything personal is blanked, as if
    /// the page were still in its sleeve.
    var masked = false

    private var record: MRZRecord { identity.record }
    private var passport: Bool { record.documentCode.hasPrefix("P") }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            HStack(alignment: .top, spacing: 16) {
                photo
                fields
            }
            mrz
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 8)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(masked
            ? "\(kind), ending \(lastCharacters)"
            : "\(record.givenNames) \(record.surname), \(Country.name(record.issuingState)) \(kind)")
    }

    private var kind: String { passport ? "passport" : "identity card" }
    private var lastCharacters: String { String(record.documentNumber.suffix(4)) }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(passport ? "PASSPORT" : "IDENTITY CARD")
                .font(.system(.subheadline, design: .serif).weight(.bold))
                .tracking(3)
                .foregroundStyle(Paper.ink)
                .lineLimit(1)
                .fixedSize()
            Text(Country.name(record.issuingState).uppercased())
                .font(.system(.caption2, design: .serif).weight(.semibold))
                .tracking(1.2)
                .foregroundStyle(Paper.faded)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Spacer(minLength: 8)
            if identity.sample {
                Stamp("SPECIMEN")
            }
            Text(Country.flag(record.issuingState))
                .font(.title3)
        }
    }

    // MARK: Portrait

    private var photo: some View {
        ZStack {
            Rectangle().fill(Color.white.opacity(0.7))
            if let portrait, !masked {
                Image(uiImage: portrait).resizable().scaledToFill()
            } else {
                Image(systemName: "person.fill")
                    .font(.system(size: 34, weight: .light))
                    .foregroundStyle(Paper.ink.opacity(0.25))
            }
        }
        .frame(width: 92, height: 118)
        .clipShape(.rect(cornerRadius: 3))
        .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(Paper.gold.opacity(0.7), lineWidth: 1))
        .overlay(alignment: .bottomTrailing) {
            if !masked {
                // The laminate's holographic sheen.
                LinearGradient(colors: [.white.opacity(0), .white.opacity(0.35), .white.opacity(0)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    .clipShape(.rect(cornerRadius: 3))
                    .allowsHitTesting(false)
            }
        }
        .accessibilityHidden(true)
    }

    // MARK: Fields

    private var fields: some View {
        VStack(alignment: .leading, spacing: 9) {
            Field("Surname", value: record.surname.capitalized, masked: masked)
            Field("Given Names", value: record.givenNames.capitalized, masked: masked)
            HStack(alignment: .top, spacing: 14) {
                Field("Nationality", value: record.nationality, masked: masked)
                Field("Date of Birth", value: MRZFormat.pretty(record.dateOfBirth, birth: true), masked: masked)
                Field("Sex", value: record.gender == "<" ? "X" : record.gender, masked: masked)
            }
            HStack(alignment: .top, spacing: 14) {
                Field(passport ? "Passport No." : "Document No.",
                      value: masked ? "•••••\(lastCharacters)" : record.documentNumber,
                      masked: false,
                      monospaced: true)
                Field("Date of Expiry", value: MRZFormat.pretty(record.dateOfExpiry, birth: false), masked: masked,
                      alert: !masked && MRZFormat.isExpired(record.dateOfExpiry))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: MRZ

    private var mrz: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(mrzLines.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.system(size: 13, weight: .regular, design: .monospaced))
                    .kerning(1.1)
                    .lineLimit(1)
                    .minimumScaleFactor(0.5)
            }
        }
        .foregroundStyle(Paper.ink.opacity(masked ? 0.45 : 0.9))
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 4)
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.5), in: .rect(cornerRadius: 3))
        .accessibilityHidden(true)
    }

    /// The MRZ as printed, or with every character past the document code
    /// and issuer turned into filler when masked.
    private var mrzLines: [String] {
        let lines = record.lines.isEmpty ? [record.documentCode] : record.lines
        guard masked else { return lines }
        return lines.enumerated().map { index, line in
            let keep = index == 0 ? min(5, line.count) : 0
            return String(line.prefix(keep)) + String(repeating: "<", count: max(0, line.count - keep))
        }
    }
}

/// One printed field: its caption in small capitals, its value beneath.
private struct Field: View {
    var caption: String
    var value: String
    var masked: Bool
    var monospaced = false
    var alert = false

    init(_ caption: String, value: String, masked: Bool, monospaced: Bool = false, alert: Bool = false) {
        self.caption = caption
        self.value = value
        self.masked = masked
        self.monospaced = monospaced
        self.alert = alert
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(caption.uppercased())
                .font(.system(size: 8.5, weight: .semibold, design: .serif))
                .tracking(0.8)
                .foregroundStyle(Paper.faded)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            if masked {
                Text(String(repeating: "•", count: min(max(value.count, 4), 10)))
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(Paper.ink.opacity(0.35))
            } else {
                Text(value)
                    .font(monospaced ? .system(.subheadline, design: .monospaced).weight(.medium) : .system(.subheadline, design: .serif).weight(.semibold))
                    .foregroundStyle(alert ? Color.orange : Paper.ink)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// A rubber stamp, slightly askew.
private struct Stamp: View {
    var text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(.caption2, design: .serif).weight(.heavy))
            .tracking(1.5)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(lineWidth: 1.5))
            .foregroundStyle(Color(red: 0.72, green: 0.16, blue: 0.18).opacity(0.75))
            .rotationEffect(.degrees(-6))
    }
}

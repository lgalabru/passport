import Foundation
import ImageIO
import UIKit

enum MRZFormat {
    /// `YYMMDD` to a date. Birth dates in the future belong to the last century;
    /// expiry dates are assumed to fall between 1970 and 2069.
    static func date(_ yymmdd: String, birth: Bool) -> Date? {
        guard yymmdd.count == 6, let yy = Int(yymmdd.prefix(2)),
              let mm = Int(yymmdd.dropFirst(2).prefix(2)), let dd = Int(yymmdd.suffix(2)) else { return nil }
        let thisYear = Calendar.current.component(.year, from: Date()) % 100
        let century = birth ? (yy > thisYear ? 1900 : 2000) : (yy >= 70 ? 1900 : 2000)
        return Calendar(identifier: .gregorian).date(from: DateComponents(year: century + yy, month: mm, day: dd))
    }

    static func pretty(_ yymmdd: String, birth: Bool) -> String {
        guard let date = date(yymmdd, birth: birth) else { return yymmdd }
        return date.formatted(.dateTime.day(.twoDigits).month(.abbreviated).year())
    }

    static func age(_ yymmdd: String) -> Int? {
        guard let date = date(yymmdd, birth: true) else { return nil }
        return Calendar.current.dateComponents([.year], from: date, to: Date()).year
    }

    static func isExpired(_ yymmdd: String) -> Bool {
        guard let date = date(yymmdd, birth: false) else { return false }
        return date < Date()
    }

    static func yymmdd(_ date: Date) -> String {
        let c = Calendar(identifier: .gregorian).dateComponents([.year, .month, .day], from: date)
        return String(format: "%02d%02d%02d", (c.year ?? 0) % 100, c.month ?? 0, c.day ?? 0)
    }
}

/// ISO 3166 alpha-3 (as printed in the MRZ) to a flag and a name.
enum Country {
    private static let alpha2: [String: String] = [
        "AFG": "AF", "ALB": "AL", "DZA": "DZ", "AND": "AD", "AGO": "AO", "ARG": "AR", "ARM": "AM", "AUS": "AU",
        "AUT": "AT", "AZE": "AZ", "BHS": "BS", "BHR": "BH", "BGD": "BD", "BLR": "BY", "BEL": "BE", "BEN": "BJ",
        "BOL": "BO", "BIH": "BA", "BWA": "BW", "BRA": "BR", "BGR": "BG", "BFA": "BF", "KHM": "KH", "CMR": "CM",
        "CAN": "CA", "CHL": "CL", "CHN": "CN", "COL": "CO", "CRI": "CR", "CIV": "CI", "HRV": "HR", "CUB": "CU",
        "CYP": "CY", "CZE": "CZ", "DNK": "DK", "DOM": "DO", "ECU": "EC", "EGY": "EG", "SLV": "SV", "EST": "EE",
        "ETH": "ET", "FIN": "FI", "FRA": "FR", "GEO": "GE", "D": "DE", "DEU": "DE", "GHA": "GH", "GRC": "GR",
        "GTM": "GT", "HND": "HN", "HKG": "HK", "HUN": "HU", "ISL": "IS", "IND": "IN", "IDN": "ID", "IRN": "IR",
        "IRQ": "IQ", "IRL": "IE", "ISR": "IL", "ITA": "IT", "JAM": "JM", "JPN": "JP", "JOR": "JO", "KAZ": "KZ",
        "KEN": "KE", "KOR": "KR", "KWT": "KW", "LVA": "LV", "LBN": "LB", "LTU": "LT", "LUX": "LU", "MAC": "MO",
        "MYS": "MY", "MLT": "MT", "MEX": "MX", "MDA": "MD", "MCO": "MC", "MNG": "MN", "MNE": "ME", "MAR": "MA",
        "NLD": "NL", "NZL": "NZ", "NGA": "NG", "MKD": "MK", "NOR": "NO", "OMN": "OM", "PAK": "PK", "PAN": "PA",
        "PRY": "PY", "PER": "PE", "PHL": "PH", "POL": "PL", "PRT": "PT", "QAT": "QA", "ROU": "RO", "RUS": "RU",
        "SAU": "SA", "SEN": "SN", "SRB": "RS", "SGP": "SG", "SVK": "SK", "SVN": "SI", "ZAF": "ZA", "ESP": "ES",
        "LKA": "LK", "SWE": "SE", "CHE": "CH", "TWN": "TW", "THA": "TH", "TUN": "TN", "TUR": "TR", "UKR": "UA",
        "ARE": "AE", "GBR": "GB", "USA": "US", "URY": "UY", "UZB": "UZ", "VEN": "VE", "VNM": "VN", "ZWE": "ZW",
    ]

    static func flag(_ code: String) -> String {
        guard let two = alpha2[code] else { return code == "UTO" ? "🏳️" : "🌐" }
        return two.unicodeScalars.compactMap { UnicodeScalar(127_397 + $0.value) }.map(String.init).joined()
    }

    static func name(_ code: String) -> String {
        if code == "UTO" { return "Utopia" }
        guard let two = alpha2[code] else { return code }
        return Locale.current.localizedString(forRegionCode: two) ?? code
    }
}

/// Decodes an image that is still arriving: a baseline JPEG paints top-down as
/// DG2 streams off the chip. JPEG 2000 portraits appear once complete.
enum PartialImage {
    static func decode(_ data: Data, final: Bool) -> UIImage? {
        guard !data.isEmpty else { return nil }
        let source = CGImageSourceCreateIncremental(nil)
        CGImageSourceUpdateData(source, data as CFData, final)
        guard let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return nil }
        return UIImage(cgImage: image)
    }

    static func load(_ url: URL) -> UIImage? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return decode(data, final: true)
    }
}

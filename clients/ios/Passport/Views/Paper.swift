import SwiftUI

/// The passport's look: guilloché paper pages, navy ink, gold foil.
enum Paper {
    /// The printed ink: a deep navy.
    static let ink = Color(red: 0.09, green: 0.15, blue: 0.34)
    /// Secondary ink, for captions and footers.
    static let faded = Color(red: 0.09, green: 0.15, blue: 0.34).opacity(0.62)
    /// Gold foil, for accents and controls.
    static let gold = Color(red: 0.76, green: 0.58, blue: 0.24)
    /// The leather of the cover.
    static let leather = Color(red: 0.05, green: 0.10, blue: 0.25)

    /// A translucent sheet laid on the page, for rows and panels.
    static var panel: some ShapeStyle { Color.white.opacity(0.58) }

    enum Side {
        case left, right

        var image: String {
            switch self {
            case .left: "PageLeft"
            case .right: "PageRight"
            }
        }
    }
}

/// The guilloché print of one page, its inner edge the fold.
///
/// In a spread the two prints meet at the hinge, both at one scale (the
/// hinge isn't at the screen's centre, so a print is scaled to cover the
/// wider page), each pushed against the spine, so the globe, the rosette and
/// the emblem on the fold run from one page onto the other. Alone (the folded
/// screen, a sheet) a print shows from its outer edge, the fold out of sight.
struct PageBackground: View {
    var side: Paper.Side
    var spine = false
    @Environment(\.spreadHalfWidth) private var spreadHalfWidth

    /// Each print's size.
    private let artwork = CGSize(width: 740, height: 978)

    var body: some View {
        GeometryReader { proxy in
            let size = proxy.size
            let aspect = artwork.width / artwork.height
            // The two pages of a spread share one scale: the print must cover
            // the wider of them.
            let cover = max(size.width, spine ? spreadHalfWidth ?? 0 : 0)
            let height = max(size.height, cover / aspect)
            let width = height * aspect
            // The fold is the left print's trailing edge and the right print's
            // leading edge; it sits at the spine. Alone, the outer edge leads.
            let x: CGFloat = switch (side, spine) {
            case (.left, true): size.width - width
            case (.right, true): 0
            case (.left, false): 0
            case (.right, false): size.width - width
            }
            Image(side.image)
                .resizable()
                .frame(width: width, height: height)
                .offset(x: x, y: -(height - size.height) / 2)
                .frame(width: size.width, height: size.height, alignment: .topLeading)
                .clipped()
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// A page of the passport: the print behind, lists see-through, the ink navy
/// and the controls gold. Applied to each view inside a `NavigationStack` (its
/// root and what it pushes), not to the stack. The bar itself is styled by
/// `PaperAppearance` (transparent, serif), which a `toolbarBackground` here
/// would override. In a spread (`spine`) the page is see-through: `Spread`
/// draws both prints so they meet exactly at the fold.
struct PageStyle: ViewModifier {
    var side: Paper.Side
    var spine: Bool

    func body(content: Content) -> some View {
        content
            .scrollContentBackground(.hidden)
            .tint(Paper.gold)
            .foregroundStyle(Paper.ink)
            .containerBackground(for: .navigation) {
                // In a spread the `Spread` draws both prints meeting at the fold.
                if spine { Color.clear } else { PageBackground(side: side) }
            }
    }
}

extension EnvironmentValues {
    /// In a spread, the width of the wider page: what a half of the artwork
    /// has to cover on both pages for them to share one scale.
    @Entry var spreadHalfWidth: CGFloat? = nil
}

extension View {
    /// `spine`: one page of a spread, meeting the other at the hinge.
    func page(_ side: Paper.Side, spine: Bool = false) -> some View {
        modifier(PageStyle(side: side, spine: spine))
    }

    /// Rows of a `List` on the page: a sheet of translucent paper.
    func paperRows() -> some View {
        listRowBackground(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Paper.panel)
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Paper.gold.opacity(0.35), lineWidth: 0.5))
                .padding(.vertical, 1)
        )
    }

    /// A panel on the page, for content outside a `List`.
    func paperPanel(cornerRadius: CGFloat = 14) -> some View {
        background(
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(Paper.panel)
                .overlay(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous).strokeBorder(Paper.gold.opacity(0.35), lineWidth: 0.5))
        )
    }
}

/// A section title, printed as on a data page: small capitals, letter-spaced.
struct PaperHeading: View {
    var text: LocalizedStringKey

    init(_ text: LocalizedStringKey) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(.caption, design: .serif).weight(.semibold))
            .textCase(.uppercase)
            .tracking(1.6)
            .foregroundStyle(Paper.faded)
    }
}

/// A footnote on the page.
struct PaperFootnote: View {
    var text: Text

    init(_ text: Text) {
        self.text = text
    }

    init(_ string: String) {
        self.text = Text(string)
    }

    var body: some View {
        text
            .font(.footnote)
            .foregroundStyle(Paper.faded)
            .textCase(nil)
    }
}

extension Font {
    /// Titles set in the engraved serif of a data page.
    static func engraved(_ style: TextStyle, weight: Weight = .semibold) -> Font {
        .system(style, design: .serif).weight(weight)
    }
}

/// The navigation bars of every page, in the same serif and ink.
enum PaperAppearance {
    static func install() {
        let appearance = UINavigationBarAppearance()
        appearance.configureWithTransparentBackground()
        let ink = UIColor(Paper.ink)
        let large = UIFontDescriptor.preferredFontDescriptor(withTextStyle: .largeTitle).withDesign(.serif)
        let title = UIFontDescriptor.preferredFontDescriptor(withTextStyle: .headline).withDesign(.serif)
        appearance.largeTitleTextAttributes = [
            .foregroundColor: ink,
            .font: UIFont(descriptor: (large ?? .preferredFontDescriptor(withTextStyle: .largeTitle)).addingAttributes([.traits: [UIFontDescriptor.TraitKey.weight: UIFont.Weight.semibold]]), size: 0),
        ]
        appearance.titleTextAttributes = [
            .foregroundColor: ink,
            .font: UIFont(descriptor: (title ?? .preferredFontDescriptor(withTextStyle: .headline)).addingAttributes([.traits: [UIFontDescriptor.TraitKey.weight: UIFont.Weight.semibold]]), size: 0),
        ]
        UINavigationBar.appearance().standardAppearance = appearance
        UINavigationBar.appearance().scrollEdgeAppearance = appearance
        UINavigationBar.appearance().compactAppearance = appearance
        UINavigationBar.appearance().tintColor = UIColor(Paper.gold)
    }
}

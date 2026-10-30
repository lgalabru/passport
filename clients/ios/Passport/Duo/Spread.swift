import SwiftUI

/// How a window splits into pages.
///
/// On an unfolded iPhone Duo the system reserves a *division* region over the
/// hinge (`GeometryProxy.reservedRegions(kind: .division)`, iOS 27.1): content
/// must not straddle it, so the app lays out two pages, one per half, like the
/// open passport it is reading. A wide window without a hinge (an iPhone in
/// landscape) gets two pages with a drawn spine instead.
enum SpreadLayout: Equatable {
    case single
    /// Side by side: the leading page's width and the hinge gap after it.
    case pages(leading: CGFloat, gap: CGFloat, hinge: Bool)
    /// One above the other (the Duo held like a laptop): top height and gap.
    case stacked(top: CGFloat, gap: CGFloat)

    static func resolve(_ proxy: GeometryProxy) -> SpreadLayout {
        if #available(iOS 27.1, *) {
            let regions = proxy.reservedRegions(kind: .division).filter(\.isActive)
            if let region = regions.first {
                let frame = region.frame
                if frame.height >= frame.width {
                    return .pages(leading: max(0, frame.minX), gap: frame.width, hinge: true)
                }
                return .stacked(top: max(0, frame.minY), gap: frame.height)
            }
        }
        let size = proxy.size
        if size.width >= 640 && size.width > size.height * 1.15 {
            return .pages(leading: size.width / 2, gap: 0, hinge: false)
        }
        return .single
    }

    var isSpread: Bool { self != .single }
}

/// Two-page layout around the hinge, or the single-screen layout.
struct Spread<Leading: View, Trailing: View, Single: View>: View {
    /// Told whether the window is laid out as two pages, as that changes.
    var onSpread: (Bool) -> Void = { _ in }
    @ViewBuilder var leading: Leading
    @ViewBuilder var trailing: Trailing
    @ViewBuilder var single: Single
    @Environment(\.hinge) private var hinge

    var body: some View {
        GeometryReader { proxy in
            let layout = SpreadLayout.resolve(proxy)
            Group {
            switch layout {
            case .single:
                single
            case .pages(let width, let gap, let isHinge):
                HStack(spacing: 0) {
                    leading
                        .frame(width: width)
                        .overlay(alignment: .trailing) { PageGutter(edge: .trailing, depth: hinge.foldDepth) }
                    Spine(axis: .vertical, hinge: isHinge, depth: hinge.foldDepth, degrees: hinge.degrees)
                        .frame(width: max(gap, isHinge ? gap : 1))
                    trailing
                        .frame(maxWidth: .infinity)
                        .overlay(alignment: .leading) { PageGutter(edge: .leading, depth: hinge.foldDepth) }
                }
            case .stacked(let height, let gap):
                VStack(spacing: 0) {
                    leading.frame(height: height)
                    Spine(axis: .horizontal, hinge: true, depth: hinge.foldDepth, degrees: hinge.degrees)
                        .frame(height: gap)
                    trailing.frame(maxHeight: .infinity)
                }
            }
            }
            .onChange(of: layout.isSpread, initial: true) { _, spread in onSpread(spread) }
        }
        .animation(.smooth(duration: 0.45), value: hinge.status)
    }
}

/// The book's spine: what sits over the hinge.
private struct Spine: View {
    var axis: Axis
    var hinge: Bool
    var depth: Double
    var degrees: Int?

    var body: some View {
        ZStack {
            Rectangle().fill(Color(.systemBackground))
            Rectangle().fill(Color(.separator))
                .frame(width: axis == .vertical ? 0.5 : nil, height: axis == .horizontal ? 0.5 : nil)
        }
        .ignoresSafeArea()
    }
}

/// Shading where a page curves into the spine; deepens as the Duo folds.
private struct PageGutter: View {
    var edge: HorizontalEdge
    var depth: Double

    var body: some View {
        LinearGradient(
            colors: [.black.opacity(0.22 * depth), .clear],
            startPoint: edge == .trailing ? .trailing : .leading,
            endPoint: edge == .trailing ? .leading : .trailing
        )
        .frame(width: 12 + 36 * depth)
        .allowsHitTesting(false)
        .ignoresSafeArea()
    }
}

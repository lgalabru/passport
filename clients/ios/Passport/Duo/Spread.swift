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
            // The fold's region is active only while the device is partly
            // folded; flat, it is inactive and zero wide, but still says where
            // the hinge is. That matters: on the inner display the status bar
            // and Dynamic Island sit in the trailing safe area, so half of the
            // safe area isn't the hinge; the hinge is some 40 points further.
            let regions = proxy.reservedRegions(kind: .division, options: .includeInactive)
            if let region = regions.first(where: \.isActive) ?? regions.first {
                // The region's frame includes 20-point margins either side of the
                // fold, and runs the full screen, safe areas included. A region
                // that doesn't fit the screen (the cover display sees the hinge's
                // for a moment while folding) is no division of this view.
                let frame = region.frame
                let safe = proxy.safeAreaInsets
                let screen = CGRect(
                    x: -safe.leading, y: -safe.top,
                    width: proxy.size.width + safe.leading + safe.trailing,
                    height: proxy.size.height + safe.top + safe.bottom
                ).insetBy(dx: -1, dy: -1)
                if screen.contains(frame) {
                    if frame.height >= frame.width, frame.minX > 0, frame.maxX < proxy.size.width {
                        return .pages(leading: frame.minX, gap: frame.width, hinge: true)
                    }
                    if frame.width > frame.height, frame.minY > 0, frame.maxY < proxy.size.height {
                        return .stacked(top: frame.minY, gap: frame.height)
                    }
                }
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
                // The fold itself, in the middle of the division's margins.
                let fold = width + gap / 2
                // The pages' prints run under the margins and the safe areas, meeting at the fold.
                let half = max(fold, proxy.size.width + proxy.safeAreaInsets.trailing - fold)
                ZStack {
                    HStack(spacing: 0) {
                        PageBackground(side: .left, spine: true).frame(width: fold)
                        PageBackground(side: .right, spine: true).frame(maxWidth: .infinity)
                    }
                    .environment(\.spreadHalfWidth, half)
                    .ignoresSafeArea()
                    HStack(spacing: 0) {
                        leading
                            .frame(width: width)
                            .overlay(alignment: .trailing) { PageGutter(edge: .trailing, depth: hinge.foldDepth) }
                        Spine(axis: .vertical, hinge: isHinge, depth: hinge.foldDepth, degrees: hinge.degrees)
                            .frame(width: max(gap, 1))
                        trailing
                            .frame(maxWidth: .infinity)
                            .overlay(alignment: .leading) { PageGutter(edge: .leading, depth: hinge.foldDepth) }
                    }
                }
            case .stacked(let height, let gap):
                ZStack {
                    VStack(spacing: 0) {
                        PageBackground(side: .left).frame(height: height + gap / 2)
                        PageBackground(side: .right).frame(maxHeight: .infinity)
                    }
                    .ignoresSafeArea()
                    VStack(spacing: 0) {
                        leading.frame(height: height)
                        Spine(axis: .horizontal, hinge: true, depth: hinge.foldDepth, degrees: hinge.degrees)
                            .frame(height: gap)
                        trailing.frame(maxHeight: .infinity)
                    }
                }
            }
            }
            .onChange(of: layout.isSpread, initial: true) { _, spread in onSpread(spread) }
        }
        .animation(.smooth(duration: 0.45), value: hinge.status)
    }
}

/// The book's spine: what sits over the hinge. The pages' prints run under
/// it; it only deepens into a crease as the Duo folds.
private struct Spine: View {
    var axis: Axis
    var hinge: Bool
    var depth: Double
    var degrees: Int?

    var body: some View {
        LinearGradient(
            colors: [.clear, .black.opacity(0.18 * depth + (hinge ? 0.04 : 0)), .clear],
            startPoint: axis == .vertical ? .leading : .top,
            endPoint: axis == .vertical ? .trailing : .bottom
        )
        .allowsHitTesting(false)
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

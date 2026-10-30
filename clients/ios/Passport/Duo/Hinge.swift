import Observation
import SwiftUI
import UIKit

/// The fold of an iPhone Duo, as `UIHingeInteraction` reports it. On devices
/// without a hinge (or before iOS 27.1) `isAvailable` stays false.
@Observable
final class HingeState {
    enum Status: Equatable {
        case unavailable, closed, partiallyOpen, fullyOpen
    }

    var status: Status = .unavailable
    /// Opening angle in radians: 0 closed, π flat.
    var angle: Double?

    var isAvailable: Bool { status != .unavailable }

    /// 0 when flat, rising to 1 as the halves fold towards each other; drives
    /// the shading in the spine between the two pages.
    var foldDepth: Double {
        guard let angle, status == .partiallyOpen else { return 0 }
        return max(0, min(1, 1 - angle / .pi))
    }

    var degrees: Int? { angle.map { Int(($0 * 180 / .pi).rounded()) } }
}

/// Installs a `UIHingeInteraction` in the hierarchy and mirrors it into a
/// `HingeState`. Put it once, behind the root view.
struct HingeObserver: UIViewRepresentable {
    let state: HingeState

    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        view.isUserInteractionEnabled = false
        if #available(iOS 27.1, *) {
            let state = self.state
            let interaction = UIHingeInteraction { _, update in
                guard let hinge = update.hinge else {
                    state.status = .unavailable
                    state.angle = nil
                    return
                }
                state.angle = Double(hinge.angle)
                switch hinge.status {
                case .closed: state.status = .closed
                case .partiallyOpen: state.status = .partiallyOpen
                case .fullyOpen: state.status = .fullyOpen
                default: state.status = .unavailable
                }
            }
            view.addInteraction(interaction)
        }
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {}
}

extension HingeState {
    /// What views see before the app injects the observed hinge.
    static let unavailable = HingeState()
}

extension EnvironmentValues {
    @Entry var hinge = HingeState.unavailable
}

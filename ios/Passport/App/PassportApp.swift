import SwiftUI

@main
struct PassportApp: App {
    @State private var model = AppModel()
    @State private var hinge = HingeState()
    @Environment(\.scenePhase) private var phase

    init() {
        NotificationRouter.shared.install()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .environment(\.hinge, hinge)
                .background(HingeObserver(state: hinge).frame(width: 0, height: 0))
                .onOpenURL { model.open($0) }
                .onAppear { NotificationRouter.shared.open = { [model] in model.open($0) } }
                .onChange(of: phase) { _, phase in
                    if phase != .active { model.conceal() }
                }
                .overlay {
                    // Identity data stays out of the app switcher.
                    if phase != .active {
                        Rectangle().fill(.regularMaterial).ignoresSafeArea()
                    }
                }
        }
    }
}

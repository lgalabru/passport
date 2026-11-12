import SwiftUI

/// One screen: a stack, with requests as sheets. An unfolded iPhone Duo: the
/// document on the left half, the request or the selected detail on the right,
/// split at the hinge. Both read the same `AppModel`, so folding mid-request
/// keeps the request on screen.
struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Spread(onSpread: { model.unfolded = $0 }) {
            NavigationStack {
                HomeView(spread: true)
                    .page(.left, spine: true)
            }
        } trailing: {
            NavigationStack {
                SecondPage()
                    .page(.right, spine: true)
            }
        } single: {
            if model.showsCover {
                CoverView(pending: model.pendingRequests) { model.openCover() }
                    .transition(.opacity)
            } else {
                SingleScreen()
            }
        }
        .animation(.smooth(duration: 0.4), value: model.showsCover)
        .sheet(item: Binding(get: { model.setup }, set: { if $0 == nil { model.setup = nil } })) { setup in
            SetupFlow(setup: setup)
        }
    }
}

extension Setup: Identifiable {
    var id: ObjectIdentifier { ObjectIdentifier(self) }
}

private struct SecondPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let session = model.session {
            RequestsPage(sessions: [session])
        } else {
            switch model.selection {
            case .document: DocumentDetails()
            case .presentation(let id):
                if let presentation = model.history.first(where: { $0.id == id }) {
                    PresentationDetail(presentation: presentation)
                }
            case nil: PagePlaceholder()
            }
        }
    }
}

private struct SingleScreen: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            HomeView()
                .page(.left)
                .navigationDestination(for: AppModel.Selection.self) { selection in
                    Group {
                        switch selection {
                        case .document: DocumentDetails()
                        case .presentation(let id):
                            if let presentation = model.history.first(where: { $0.id == id }) {
                                PresentationDetail(presentation: presentation)
                            }
                        }
                    }
                    .page(.right)
                }
        }
        // Only the sheet's own buttons end a request: this sheet is also torn
        // down when the Duo unfolds and the request moves to the right page.
        .sheet(item: Binding(get: { model.setup == nil ? model.session : nil }, set: { _ in })) { session in
            RequestView(session: session)
                .presentationDetents([.large])
                .interactiveDismissDisabled()
        }
    }
}

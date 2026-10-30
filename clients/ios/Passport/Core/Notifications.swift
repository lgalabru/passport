import Foundation
import UserNotifications

/// Requests that arrive as notifications: a relying party (or its push
/// service) sends one whose `request` field is the OpenID4VP link; tapping it
/// opens the request.
final class NotificationRouter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationRouter()

    /// Where tapped requests go; set once the app model exists.
    var open: ((URL) -> Void)? {
        didSet {
            if let url = pending, let open {
                pending = nil
                open(url)
            }
        }
    }

    private var pending: URL?

    func install() {
        UNUserNotificationCenter.current().delegate = self
    }

    /// Ask once, after a passport is added: that is when requests start to matter.
    @discardableResult
    func requestPermission() async -> Bool {
        (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])) ?? false
    }

    // The completion-handler forms, not the async ones: UIKit must get the
    // completion on the main thread, and the async variants would finish on a
    // background executor (an assertion in UIApplication, then SIGABRT).

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let text = response.notification.request.content.userInfo["request"] as? String
        DispatchQueue.main.async {
            if let url = text.flatMap(URL.init(string:)) {
                if let open = self.open { open(url) } else { self.pending = url }
            }
            completionHandler()
        }
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}

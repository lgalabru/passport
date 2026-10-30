// Prints the on-screen rectangle (`x,y,w,h`, points) of DeviceHub's
// "iPhone Duo" window, for `screencapture -R`. Exits non-zero when it is not
// on this desktop.
import CoreGraphics
import Foundation

let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID)
    as? [[String: Any]] ?? []
let match = windows.first { window in
    (window[kCGWindowOwnerName as String] as? String)?.replacingOccurrences(of: " ", with: "") == "DeviceHub"
        && (window[kCGWindowName as String] as? String ?? "").contains("iPhone Duo")
        && window[kCGWindowLayer as String] as? Int == 0
}
guard let bounds = match?[kCGWindowBounds as String] as? [String: CGFloat] else {
    FileHandle.standardError.write(Data("No DeviceHub window showing the iPhone Duo on this desktop.\n".utf8))
    exit(1)
}
print([bounds["X"], bounds["Y"], bounds["Width"], bounds["Height"]].map { String(Int($0 ?? 0)) }.joined(separator: ","))

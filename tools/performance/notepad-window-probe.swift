#!/usr/bin/env swift
import CoreGraphics
import Foundation

let timeout = CommandLine.arguments.count > 1 ? Double(CommandLine.arguments[1]) ?? 120.0 : 120.0
let needle = CommandLine.arguments.count > 2 ? CommandLine.arguments[2].lowercased() : "notepad"
let deadline = Date().addingTimeInterval(timeout)

guard CGPreflightScreenCaptureAccess() else {
    fputs("CoreGraphics screen-capture access is unavailable for this process\n", stderr)
    exit(2)
}

repeat {
    let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
    if let windows = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[String: Any]] {
        for window in windows {
            let owner = (window[kCGWindowOwnerName as String] as? String ?? "").lowercased()
            let title = (window[kCGWindowName as String] as? String ?? "").lowercased()
            let bounds = window[kCGWindowBounds as String] as? [String: Any]
            let width = bounds?["Width"] as? Double ?? 0
            let height = bounds?["Height"] as? Double ?? 0
            if (owner.contains(needle) || title.contains(needle)) && width >= 100 && height >= 80 {
                let elapsed = timeout - deadline.timeIntervalSinceNow
                print(String(format: "%.6f\t%@\t%@", elapsed, owner, title))
                exit(EXIT_SUCCESS)
            }
        }
    }
    Thread.sleep(forTimeInterval: 0.05)
} while Date() < deadline

fputs("timed out waiting for visible Notepad window\n", stderr)
exit(EXIT_FAILURE)

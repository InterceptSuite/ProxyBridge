import Foundation
import NetworkExtension
import os.log

// Why the extension started or stopped, written where it can be found afterwards.
//
// The extension used to log nothing about its own life cycle, so when macOS started it and stopped it
// again within milliseconds (issue #282) there was no way to tell why. Every line goes to the unified
// log (Console.app, or `log show --predicate 'subsystem == "com.interceptsuite.ProxyBridge.extension"'`).
// Never put credentials, host names or other traffic details in a message here.
enum ProviderDiagnostics {
    private static let osLog = OSLog(subsystem: "com.interceptsuite.ProxyBridge.extension", category: "provider")

    static func note(_ message: String, error: Bool = false) {
        os_log("%{public}@", log: osLog, type: error ? .error : .default, message)
    }

    // NEProviderStopReason, spelled out. The raw values are used so a reason newer than this build
    // still prints its number.
    private static let reasons: [Int: String] = [
        0: "none",
        1: "stopped by the user",
        2: "the provider failed",
        3: "no network available",
        4: "the network changed and could not be recovered",
        5: "the provider was disabled",
        6: "authentication was cancelled",
        7: "the configuration failed",
        8: "idle timeout",
        9: "the configuration was disabled",
        10: "the configuration was removed",
        11: "replaced by another configuration",
        12: "the user logged out",
        13: "the user was switched",
        14: "the connection failed",
        15: "the Mac went to sleep",
        16: "the app was updated",
        17: "internal error",
    ]

    static func text(for reason: NEProviderStopReason) -> String {
        let raw = reason.rawValue
        return "\(reasons[raw] ?? "unknown reason") (\(raw))"
    }
}

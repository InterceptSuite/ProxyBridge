import Foundation
import os

/// The system log of the tunnel. Dynamic text is redacted unless a device is attached for debugging.
struct TunnelLogger {
    private let logger: Logger

    init(category: String) {
        logger = Logger(subsystem: "com.interceptsuite.ProxyBridge.ios.tunnel", category: category)
    }

    func info(_ message: String) {
        logger.info("\(message)")
    }

    func warning(_ message: String) {
        logger.warning("\(message)")
    }

    func error(_ message: String) {
        logger.error("\(message)")
    }
}

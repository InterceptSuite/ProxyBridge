import Foundation

/// Keeps the config in the app group container so the app and the tunnel extension read the same file.
final class ConfigStore {
    static let appGroup = "group.com.interceptsuite.ProxyBridge"
    static let shared = ConfigStore()

    private let fileURL: URL?
    private let lock = NSLock()

    private init() {
        fileURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup)?
            .appendingPathComponent("config.json")
    }

    func load() -> AppConfig {
        lock.lock()
        defer { lock.unlock() }
        guard let fileURL,
              let data = try? Data(contentsOf: fileURL),
              let config = try? JSONDecoder().decode(AppConfig.self, from: data) else {
            return AppConfig()
        }
        return config
    }

    func save(_ config: AppConfig) {
        lock.lock()
        defer { lock.unlock() }
        guard let fileURL, let data = try? JSONEncoder().encode(config) else { return }
        // The tunnel starts while the device is locked after a reboot, so the file must stay readable then.
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}

import Combine
import NetworkExtension

/// Installs the VPN configuration and turns the tunnel on and off. iOS asks the user to allow the
/// configuration the first time.
@MainActor
final class TunnelManager: ObservableObject {
    private static let providerBundleId = "com.interceptsuite.ProxyBridge.ios.tunnel"

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published var errorMessage: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: AnyCancellable?

    var isOn: Bool {
        [.connected, .connecting, .reasserting].contains(status)
    }

    var isBusy: Bool {
        [.connecting, .disconnecting].contains(status)
    }

    func load() async {
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        manager = managers?.first
        observeStatus()
    }

    func setEnabled(_ enabled: Bool) async {
        errorMessage = nil
        if !enabled {
            manager?.connection.stopVPNTunnel()
            return
        }
        do {
            try await installedManager().connection.startVPNTunnel()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Tells a running tunnel to read the saved config again.
    func configDidChange() {
        guard isOn, let session = manager?.connection as? NETunnelProviderSession else { return }
        try? session.sendProviderMessage(Data([1])) { _ in }
    }

    private func installedManager() async throws -> NETunnelProviderManager {
        let manager = self.manager ?? NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = Self.providerBundleId
        // required by the API, the tunnel never connects to it
        configuration.serverAddress = "ProxyBridge"
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "ProxyBridge"
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        self.manager = manager
        observeStatus()
        return manager
    }

    private func observeStatus() {
        guard let connection = manager?.connection else { return }
        status = connection.status
        statusObserver = NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange, object: connection)
            .sink { [weak self] _ in self?.status = connection.status }
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .connected: return "On"
        case .connecting: return "Connecting"
        case .disconnecting: return "Turning off"
        case .reasserting: return "Reconnecting"
        case .disconnected, .invalid: return "Off"
        @unknown default: return "Off"
        }
    }
}

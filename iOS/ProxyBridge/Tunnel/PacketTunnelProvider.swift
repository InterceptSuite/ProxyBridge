import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let server = LocalSocks5Server()
    private let log = TunnelLogger(category: "tunnel")

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // the physical network's DNS servers are only visible before the tunnel changes the resolver
        server.dnsUpstreams = SystemResolvers.current()
        log.info("starting")
        reloadConfig()
        DNSMapStore.shared.clear()

        setTunnelNetworkSettings(Self.networkSettings()) { [weak self] error in
            if let error {
                self?.log.error("network settings failed: \(error.localizedDescription)")
                return completionHandler(error)
            }
            self?.startStack(completionHandler: completionHandler)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopping: \(String(describing: reason))")
        HevTunnel.stop()
        server.stop()
        DNSMapStore.shared.clear()
        completionHandler()
    }

    /// The app sends a message after it saves new rules.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        reloadConfig()
        completionHandler?(nil)
    }

    private func reloadConfig() {
        server.update(ConfigStore.shared.load())
    }

    private func startStack(completionHandler: @escaping (Error?) -> Void) {
        guard let tunFd = HevTunnel.tunnelFileDescriptor() else {
            log.error("no utun file descriptor found")
            return completionHandler(TunnelError.noTunnelDevice)
        }
        server.start { result in
            switch result {
            case .success(let port):
                HevTunnel.start(tunFd: tunFd, socksPort: port, mtu: TunnelNetwork.mtu) { [weak self] code in
                    if code != 0 { self?.log.error("hev stopped with code \(code)") }
                }
                completionHandler(nil)
            case .failure(let error):
                self.log.error("router failed to start: \(error.localizedDescription)")
                completionHandler(error)
            }
        }
    }

    private static func networkSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: [TunnelNetwork.address], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: [TunnelNetwork.addressV6], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: [TunnelNetwork.dnsServer])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        settings.mtu = NSNumber(value: TunnelNetwork.mtu)
        return settings
    }
}

private enum TunnelError: LocalizedError {
    case noTunnelDevice

    var errorDescription: String? { "The tunnel interface could not be found." }
}

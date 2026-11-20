import Foundation

/// Addresses of the virtual interface. The DNS address is only a target: queries sent to it are answered by the tunnel.
enum TunnelNetwork {
    static let address = "10.64.0.2"
    static let dnsServer = "10.64.0.1"
    static let addressV6 = "fd00::2"
    static let mtu = 1500
}

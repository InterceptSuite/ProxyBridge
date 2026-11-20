import Foundation

enum RuleAction: String, Codable, CaseIterable {
    case proxy
    case direct
    case block

    var label: String { rawValue.capitalized }
}

enum RuleProtocol: String, Codable, CaseIterable {
    case any
    case tcp
    case udp

    var label: String {
        switch self {
        case .any: return "TCP and UDP"
        case .tcp: return "TCP"
        case .udp: return "UDP"
        }
    }
}

/// iOS does not tell the tunnel which app sent a packet, so a rule only describes the destination.
struct ProxyRule: Codable, Identifiable, Equatable {
    var id = UUID()
    var name = ""
    /// Semicolon separated domains (wildcards allowed), IP addresses or CIDR blocks. Empty matches any host.
    var hosts = ""
    /// Semicolon separated ports. Empty matches any port.
    var ports = ""
    var proto: RuleProtocol = .any
    var action: RuleAction = .proxy
    /// Proxy used when the action is proxy. Nil means the default proxy.
    var proxyId: UUID?
    var enabled = true

    var title: String {
        if !name.isEmpty { return name }
        return hosts.isEmpty ? "All traffic" : hosts
    }
}

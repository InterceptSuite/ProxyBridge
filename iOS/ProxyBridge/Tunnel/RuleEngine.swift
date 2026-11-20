import Foundation

struct FlowInfo {
    let ip: String
    let port: Int
    let isUDP: Bool
    /// Names that resolved to `ip`, learned from DNS answers.
    let domains: [String]
}

enum Route: CustomStringConvertible {
    case direct
    case block
    case proxy(ProxyConfig)

    var description: String {
        switch self {
        case .direct: return "direct"
        case .block: return "block"
        case .proxy(let proxy): return "proxy \(proxy.displayName)"
        }
    }
}

/// Picks a route for a flow. Rules are parsed once when the engine is built, the first matching rule wins.
struct RuleEngine {
    private let rules: [CompiledRule]
    private let proxies: [ProxyConfig]
    private let defaultAction: RuleAction

    init(config: AppConfig) {
        rules = config.rules.filter(\.enabled).map(CompiledRule.init)
        proxies = config.proxies
        defaultAction = config.defaultAction
    }

    func route(for flow: FlowInfo) -> Route {
        let ip = RuleMatch.ipToBytes(flow.ip)
        let rule = rules.first { $0.matches(flow, ip: ip) }
        switch rule?.action ?? defaultAction {
        case .direct:
            return .direct
        case .block:
            return .block
        case .proxy:
            let chosen = proxies.first { $0.id == rule?.proxyId } ?? proxies.first
            return chosen.map(Route.proxy) ?? .direct
        }
    }
}

private enum HostPattern {
    case any
    case address([UInt8])
    case network([UInt8], bits: Int)
    case name(String)

    init(_ text: String) {
        if text == "*" {
            self = .any
        } else if let address = RuleMatch.ipToBytes(text) {
            self = .address(address)
        } else if let slash = text.firstIndex(of: "/"),
                  let network = RuleMatch.ipToBytes(String(text[..<slash])),
                  let bits = Int(text[text.index(after: slash)...]) {
            self = .network(network, bits: bits)
        } else {
            self = .name(text)
        }
    }

    func matches(ip: [UInt8]?, domains: [String]) -> Bool {
        switch self {
        case .any:
            return true
        case .address(let address):
            return ip == address
        case .network(let network, let bits):
            return ip.map { RuleMatch.prefixEqual($0, network, bits: bits) } ?? false
        case .name(let pattern):
            // "*.example.com" also covers example.com itself
            let apex = pattern.hasPrefix("*.") ? String(pattern.dropFirst(2)) : nil
            return domains.contains { RuleMatch.glob(pattern, $0) || $0 == apex }
        }
    }
}

private struct CompiledRule {
    let action: RuleAction
    let proxyId: UUID?
    private let proto: RuleProtocol
    private let hosts: [HostPattern]
    /// Nil matches any port.
    private let ports: Set<Int>?

    init(_ rule: ProxyRule) {
        action = rule.action
        proxyId = rule.proxyId
        proto = rule.proto

        let patterns = Self.items(rule.hosts).map(HostPattern.init)
        hosts = patterns.isEmpty ? [.any] : patterns

        let portItems = Self.items(rule.ports, lowercase: false)
        ports = portItems.isEmpty || portItems.contains("*") ? nil : Set(portItems.compactMap { Int($0) })
    }

    func matches(_ flow: FlowInfo, ip: [UInt8]?) -> Bool {
        switch proto {
        case .tcp where flow.isUDP, .udp where !flow.isUDP:
            return false
        default:
            break
        }
        if let ports, !ports.contains(flow.port) { return false }
        return hosts.contains { $0.matches(ip: ip, domains: flow.domains) }
    }

    private static func items(_ text: String, lowercase: Bool = true) -> [String] {
        text.split(separator: ";")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .map { lowercase ? $0.lowercased() : $0 }
    }
}

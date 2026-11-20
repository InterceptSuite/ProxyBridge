import Foundation

enum ProxyKind: String, Codable, CaseIterable {
    case socks5
    case http

    var label: String { self == .socks5 ? "SOCKS5" : "HTTP" }
}

struct ProxyConfig: Codable, Identifiable, Equatable {
    var id = UUID()
    var name = ""
    var kind: ProxyKind = .socks5
    var host = ""
    var port = 1080
    var username = ""
    var password = ""

    var displayName: String { name.isEmpty ? "\(host):\(port)" : name }
    var hasCredentials: Bool { !username.isEmpty }
}

/// Everything the app edits and the tunnel reads. The first proxy is the default one.
struct AppConfig: Codable, Equatable {
    var proxies: [ProxyConfig] = []
    var rules: [ProxyRule] = []
    var defaultAction: RuleAction = .direct
}

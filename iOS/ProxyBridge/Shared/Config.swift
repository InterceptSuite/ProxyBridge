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
    /// Send the proxy the site's name instead of its IP address when the phone looked the name up.
    var sendHostname = true

    var displayName: String { name.isEmpty ? "\(host):\(port)" : name }
    var hasCredentials: Bool { !username.isEmpty }
}

extension ProxyConfig {
    /// A config saved before an option existed has no value for it, which must not fail the whole file.
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        kind = try values.decode(ProxyKind.self, forKey: .kind)
        host = try values.decode(String.self, forKey: .host)
        port = try values.decode(Int.self, forKey: .port)
        username = try values.decode(String.self, forKey: .username)
        password = try values.decode(String.self, forKey: .password)
        sendHostname = try values.decodeIfPresent(Bool.self, forKey: .sendHostname) ?? true
    }
}

/// Everything the app edits and the tunnel reads. The first proxy is the default one.
struct AppConfig: Codable, Equatable {
    var proxies: [ProxyConfig] = []
    var rules: [ProxyRule] = []
    var defaultAction: RuleAction = .direct
}

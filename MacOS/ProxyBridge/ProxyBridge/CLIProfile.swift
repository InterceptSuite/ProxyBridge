import Foundation

// a profile as the command line needs it. same layout the app writes when it exports a
// profile (and keeps per profile in its preferences), read without touching the GUI's state
struct CLIProxy: Decodable, Equatable {
    let id: String
    let name: String
    let type: String
    let host: String
    let port: Int
    let username: String?
    let password: String?
    let sendDomain: Bool

    enum CodingKeys: String, CodingKey { case id, name, type, host, port, username, password, sendDomain }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        type = try c.decode(String.self, forKey: .type)
        host = try c.decode(String.self, forKey: .host)
        port = try c.decode(Int.self, forKey: .port)
        username = try c.decodeIfPresent(String.self, forKey: .username)
        password = try c.decodeIfPresent(String.self, forKey: .password)
        // proxies saved before the option existed behave like the app's default
        sendDomain = try c.decodeIfPresent(Bool.self, forKey: .sendDomain) ?? true
    }

    var label: String { "\(type.uppercased()) \(host):\(port)" }
}

struct CLIProfile {
    var name: String
    var proxies: [CLIProxy]
    var rules: [[String: Any]]      // as saved by the app: processNames, targetHosts, targetPorts, protocol, action, enabled
}

enum CLIProfileError: Error, Equatable {
    case invalid(String)
    var message: String { if case .invalid(let m) = self { return m }; return "" }
}

enum CLIProfileLoader {
    // reads a preferences value, injected so tests don't need the real app's preferences
    typealias Reader = (String) -> Any?

    // the app's preferences, read by its bundle identifier so it also works when the
    // executable is started through a link or a launcher script
    static let appReader: Reader = { key in
        CFPreferencesCopyAppValue(key as CFString, "com.interceptsuite.ProxyBridge" as CFString)
    }

    // an exported .pbprofile (json)
    static func parse(json data: Data) throws -> CLIProfile {
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw CLIProfileError.invalid("The profile is not valid JSON.")
        }
        guard obj["proxyConfigs"] != nil || obj["proxyRules"] != nil else {
            throw CLIProfileError.invalid("This does not look like a ProxyBridge macOS profile (no proxyConfigs or proxyRules). Profiles exported from the Windows app use a different layout and can't be loaded here.")
        }
        let proxies = try decodeProxies(obj["proxyConfigs"] ?? [])
        let rules = obj["proxyRules"] as? [[String: Any]] ?? []
        return CLIProfile(name: (obj["name"] as? String) ?? "profile", proxies: proxies, rules: rules)
    }

    // a profile saved in the app. the active profile lives in the working keys
    // ("proxyConfigs", "proxyRules"), the others in "profile.<name>.*" snapshots
    static func saved(named name: String, read: Reader) throws -> CLIProfile {
        let names = read("profiles") as? [String] ?? []
        guard names.contains(name) else {
            let list = names.isEmpty ? "none saved yet" : names.joined(separator: ", ")
            throw CLIProfileError.invalid("No saved profile named '\(name)' (available: \(list)). Use --list-profiles.")
        }
        let active = read("activeProfile") as? String
        let configsKey = name == active ? "proxyConfigs" : "profile.\(name).proxyConfigs"
        let rulesKey = name == active ? "proxyRules" : "profile.\(name).proxyRules"
        let proxies = try decodeProxies(read(configsKey) ?? [])
        let rules = read(rulesKey) as? [[String: Any]] ?? []
        return CLIProfile(name: name, proxies: proxies, rules: rules)
    }

    static func savedNames(read: Reader) -> (names: [String], active: String?) {
        (read("profiles") as? [String] ?? [], read("activeProfile") as? String)
    }

    // the proxy list is stored as json Data (or an already decoded array in an export)
    private static func decodeProxies(_ value: Any) throws -> [CLIProxy] {
        let data: Data
        if let d = value as? Data { data = d }
        else if JSONSerialization.isValidJSONObject(value), let d = try? JSONSerialization.data(withJSONObject: value) { data = d }
        else { return [] }
        do { return try JSONDecoder().decode([CLIProxy].self, from: data) }
        catch { throw CLIProfileError.invalid("The proxy list in the profile could not be read: \(error.localizedDescription)") }
    }

    static let maxProxies = 100
    static let maxRules = 5000

    // problems that make the profile unusable. the extension would silently drop some of these
    // (a rule with an unknown protocol) or only fail later, per connection, so they stop the run
    static func errors(for profile: CLIProfile) -> [String] {
        var out: [String] = []
        if profile.proxies.count > maxProxies { out.append("the profile has \(profile.proxies.count) proxies, the limit is \(maxProxies)") }
        if profile.rules.count > maxRules { out.append("the profile has \(profile.rules.count) rules, the limit is \(maxRules)") }
        var ids = Set<String>()
        for p in profile.proxies {
            if !ids.insert(p.id).inserted { out.append("two proxies have the same id '\(p.id)'") }
            if p.host.trimmingCharacters(in: .whitespaces).isEmpty { out.append("a \(p.type) proxy has no host") }
            if !(1...65535).contains(p.port) { out.append("proxy \(p.host) has the port \(p.port), it must be 1-65535") }
            let type = p.type.lowercased()
            if type != "socks5" && type != "http" { out.append("proxy \(p.label) has the type '\(p.type)', it must be socks5 or http") }
            if type == "socks5", (p.username?.utf8.count ?? 0) > 255 || (p.password?.utf8.count ?? 0) > 255 {
                out.append("proxy \(p.label) has a username or password longer than 255 bytes, SOCKS5 can't carry that")
            }
        }
        for (i, rule) in profile.rules.enumerated() {
            let proto = rule["protocol"] as? String ?? "BOTH"
            if !["TCP", "UDP", "BOTH"].contains(proto) { out.append("rule \(i + 1) has the protocol '\(proto)', it must be TCP, UDP or BOTH") }
        }
        return out
    }

    // problems that don't stop the run but the user should know about
    static func warnings(for profile: CLIProfile) -> [String] {
        var out: [String] = []
        let ids = Set(profile.proxies.map { $0.id })
        for (i, rule) in profile.rules.enumerated() {
            let action = rule["action"] as? String ?? "DIRECT"
            if action != "DIRECT" && action != "BLOCK" && !ids.contains(action) {
                out.append("rule \(i + 1) sends traffic to a proxy that is not in this profile, it will go direct")
            }
        }
        if profile.rules.isEmpty { out.append("the profile has no rules, nothing will be redirected") }
        return out
    }
}

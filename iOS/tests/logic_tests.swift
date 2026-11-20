// Unit checks for the rule engine, DNS parsing, SOCKS5 framing and the name map, plus a "serve" mode that runs the
// router for router_e2e.py. Compiled as main.swift by run.sh against the real tunnel sources.
import Foundation

var failures = 0
func check(_ name: String, _ condition: Bool) {
    if !condition { failures += 1; print("FAIL", name) }
}

func rule(_ hosts: String, ports: String = "", proto: RuleProtocol = .any, action: RuleAction = .block) -> ProxyRule {
    var rule = ProxyRule()
    rule.hosts = hosts
    rule.ports = ports
    rule.proto = proto
    rule.action = action
    return rule
}

func flow(_ ip: String, port: Int = 80, udp: Bool = false, domains: [String] = []) -> FlowInfo {
    FlowInfo(ip: ip, port: port, isUDP: udp, domains: domains)
}

func engine(_ rules: [ProxyRule], proxies: [ProxyConfig] = [], action: RuleAction = .direct) -> RuleEngine {
    RuleEngine(config: AppConfig(proxies: proxies, rules: rules, defaultAction: action))
}

func isBlock(_ route: Route) -> Bool { if case .block = route { return true }; return false }
func isDirect(_ route: Route) -> Bool { if case .direct = route { return true }; return false }

func proxyId(_ route: Route) -> UUID? { if case .proxy(let proxy) = route { return proxy.id }; return nil }

// MARK: serve mode

if CommandLine.arguments.count > 2, CommandLine.arguments[1] == "serve" {
    let config = try! JSONDecoder().decode(AppConfig.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2])))
    DNSMapStore.shared.record(domain: "blocked.test", ips: ["127.0.0.1"])
    DNSMapStore.shared.record(domain: "localhost", ips: ["127.0.0.1"])   // the newest name, so it is the one a proxy gets
    let server = LocalSocks5Server()
    server.update(config)
    server.dnsUpstreams = SystemResolvers.current()
    server.start { result in
        if case .success(let port) = result { print("PORT \(port)"); fflush(stdout) } else { print("start failed"); exit(1) }
    }
    dispatchMain()
}

// MARK: matching helpers

check("glob star", RuleMatch.glob("*.google.com", "mail.google.com"))
check("glob miss", !RuleMatch.glob("*.google.com", "google.org"))
check("prefix equal /20", RuleMatch.prefixEqual([192, 168, 16, 0], [192, 168, 31, 255], bits: 20))
check("prefix differs /20", !RuleMatch.prefixEqual([192, 168, 16, 0], [192, 168, 32, 1], bits: 20))
check("ip round trip v4", RuleMatch.ipString(RuleMatch.ipToBytes("10.1.2.3")!) == "10.1.2.3")
check("ip round trip v6", RuleMatch.ipString(RuleMatch.ipToBytes("2001:db8::5")!) == "2001:db8::5")

// MARK: rule engine

for (cidr, inside, outside) in [("10.0.0.0/8", "10.9.8.7", "11.0.0.1"), ("192.168.16.0/20", "192.168.31.255", "192.168.32.1"),
                                ("192.168.1.0/25", "192.168.1.100", "192.168.1.200"), ("172.16.0.0/12", "172.31.1.1", "172.32.0.1"),
                                ("2001:db8::/32", "2001:db8:1::5", "2001:db9::1")] {
    let subject = engine([rule(cidr)])
    check("cidr \(cidr) inside", isBlock(subject.route(for: flow(inside))))
    check("cidr \(cidr) outside", isDirect(subject.route(for: flow(outside))))
}
check("bad prefix length does not match", isDirect(engine([rule("10.0.0.0/99")]).route(for: flow("10.0.0.1"))))
check("single ip", isBlock(engine([rule("1.2.3.4")]).route(for: flow("1.2.3.4"))))
check("ipv6 written two ways", isBlock(engine([rule("::1")]).route(for: flow("0:0:0:0:0:0:0:1"))))
check("domain", isBlock(engine([rule("*.github.com")]).route(for: flow("1.1.1.1", domains: ["api.github.com"]))))
check("apex of a wildcard", isBlock(engine([rule("*.github.com")]).route(for: flow("1.1.1.1", domains: ["github.com"]))))
check("any of several names", isBlock(engine([rule("*.github.com")]).route(for: flow("1.1.1.1", domains: ["other.org", "api.github.com"]))))
check("empty hosts matches all", isBlock(engine([rule("")]).route(for: flow("5.5.5.5"))))
check("ports list", isBlock(engine([rule("", ports: "80; 443")]).route(for: flow("5.5.5.5", port: 443))))
check("ports star matches any port", isBlock(engine([rule("", ports: "*")]).route(for: flow("5.5.5.5", port: 8443))))
check("port miss", isDirect(engine([rule("", ports: "443")]).route(for: flow("5.5.5.5", port: 80))))
check("tcp rule skips udp", isDirect(engine([rule("", proto: .tcp)]).route(for: flow("5.5.5.5", udp: true))))
check("udp rule skips tcp", isDirect(engine([rule("", proto: .udp)]).route(for: flow("5.5.5.5"))))
check("udp rule matches udp", isBlock(engine([rule("", proto: .udp)]).route(for: flow("5.5.5.5", udp: true))))
check("first matching rule wins", isDirect(engine([rule("1.2.3.4", action: .direct), rule("", action: .block)]).route(for: flow("1.2.3.4"))))
check("disabled rule is ignored", isDirect(engine([{ var r = rule("1.2.3.4"); r.enabled = false; return r }()]).route(for: flow("1.2.3.4"))))
check("default action applies", isBlock(engine([], action: .block).route(for: flow("5.5.5.5"))))

var first = ProxyConfig(), second = ProxyConfig()
first.host = "a"
second.host = "b"
var viaSecond = rule("", action: .proxy)
viaSecond.proxyId = second.id
check("rule uses the proxy it names", proxyId(engine([viaSecond], proxies: [first, second]).route(for: flow("5.5.5.5"))) == second.id)
check("first proxy is the default", proxyId(engine([rule("", action: .proxy)], proxies: [first, second]).route(for: flow("5.5.5.5"))) == first.id)
check("proxy action without proxies is direct", isDirect(engine([rule("", action: .proxy)]).route(for: flow("5.5.5.5"))))

// MARK: config

let oldConfig = #"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","name":"x","kind":"socks5","host":"h","port":1080,"username":"","password":""}"#
check("a saved proxy without the host name option loads with it on", (try? JSONDecoder().decode(ProxyConfig.self, from: Data(oldConfig.utf8)))?.sendHostname == true)
check("the option is kept when saved", {
    var proxy = ProxyConfig()
    proxy.sendHostname = false
    let data = try! JSONEncoder().encode(proxy)
    return try! JSONDecoder().decode(ProxyConfig.self, from: data).sendHostname == false
}())

// MARK: DNS

let response: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1,
                         0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34,
                         0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x26, 0x06, 0x28, 0, 0x2, 0x20, 0, 1, 0x2, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46]
let answer = DNSParser.parse(response)
check("dns name", answer?.domain == "www.example.com")
check("dns addresses", answer?.ips == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
var loop = response
loop[12] = 0xC0
loop[13] = 12
check("dns pointer loop is rejected", DNSParser.parse(loop) == nil)
check("dns garbage is rejected", DNSParser.parse([1, 2, 3]) == nil)

// MARK: name map

let map = DNSMapStore.shared
map.clear()
map.record(domain: "Old.Example", ips: ["9.9.9.9"], now: 100)
map.record(domain: "new.example", ips: ["9.9.9.9"], now: 200)
check("names are lowercased and newest first", map.domains(forIP: "9.9.9.9") == ["new.example", "old.example"])
check("the proxy gets the newest name", map.hostname(forIP: "9.9.9.9", now: 250) == "new.example")
check("a name that is too old is not used", map.hostname(forIP: "9.9.9.9", now: 200 + 301) == nil)
check("an unknown address has no name", map.hostname(forIP: "8.8.8.8", now: 250) == nil)
check("unsafe names are refused", !DNSMapStore.isSafeHostname("bad name") && !DNSMapStore.isSafeHostname("a\r\nb") && !DNSMapStore.isSafeHostname("1.2.3.4") && !DNSMapStore.isSafeHostname(".x") && DNSMapStore.isSafeHostname("a-b_c.example"))
map.clear()

// MARK: SOCKS5 framing

let framed = Socks5.frame(host: "1.2.3.4", port: 53, payload: Data([9, 8]))!
let parsed = Socks5.parseDatagram([UInt8](framed))
check("udp frame round trip", parsed?.host == "1.2.3.4" && parsed?.port == 53 && parsed?.payload == Data([9, 8]))
check("udp frame ipv6", Socks5.parseDatagram([UInt8](Socks5.frame(host: "2001:db8::1", port: 443, payload: Data([1]))!))?.host == "2001:db8::1")
check("udp frame refuses a name", Socks5.frame(host: "example.com", port: 1, payload: Data()) == nil)
check("address encoding of a name", Socks5.encode(host: "a.io", port: 80) == [3, 4, 97, 46, 105, 111, 0, 80])

print(failures == 0 ? "logic tests: ALL PASS" : "logic tests: \(failures) FAILED")
exit(failures == 0 ? 0 : 1)

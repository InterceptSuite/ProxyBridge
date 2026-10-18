// Rule matching (ProxyRule.Matcher in AppProxyProvider.swift). Compiled as main.swift by run.sh.
import Foundation

func matcher(_ p: String, _ h: String, _ pt: String) -> ProxyRule.Matcher {
    ProxyRule.Matcher(ProxyRule(ruleId: 1, processNames: p, targetHosts: h, targetPorts: pt, ruleProtocol: .both, action: "DIRECT", enabled: true))
}
var fails = 0
func t(_ name: String, _ got: Bool, _ expected: Bool) { if got != expected { fails += 1; print("FAIL", name) } }

let chrome = ProxyRule.FlowProcess(bundleId: "com.google.Chrome", processName: "Google Chrome")
let curl = ProxyRule.FlowProcess(bundleId: "curl-abc", processName: "curl")

// process patterns
t("star", matcher("*", "*", "*").matchesProcess(chrome), true)
t("prefix glob must match the start only", matcher("chrome*", "*", "*").matchesProcess(chrome), false)
t("contains glob", matcher("*chrome*", "*", "*").matchesProcess(chrome), true)
t("exact name", matcher("curl", "*", "*").matchesProcess(curl), true)
t("list with spaces", matcher("safari; curl", "*", "*").matchesProcess(curl), true)
t("comma list", matcher("safari,curl", "*", "*").matchesProcess(curl), true)
t("trailing separator is not a wildcard", matcher("safari;", "*", "*").matchesProcess(curl), false)
t("leading separator is not a wildcard", matcher(";safari", "*", "*").matchesProcess(curl), false)
t("bundle id glob", matcher("com.google.*", "*", "*").matchesProcess(chrome), true)
t("case insensitive", matcher("CURL", "*", "*").matchesProcess(curl), true)
t("no match", matcher("firefox", "*", "*").matchesProcess(curl), false)

// ports
t("port in list", matcher("*", "*", "80,443,8000-8100").matchesPort(8050), true)
t("port exact", matcher("*", "*", "80,443").matchesPort(443), true)
t("port miss", matcher("*", "*", "80,443").matchesPort(81), false)
t("port range edge low", matcher("*", "*", "8000-8100").matchesPort(8000), true)
t("port range edge high", matcher("*", "*", "8000-8100").matchesPort(8100), true)
t("port range just out", matcher("*", "*", "8000-8100").matchesPort(8101), false)
t("all ports", matcher("*", "*", "*").matchesPort(1), true)
t("garbage port never matches", matcher("*", "*", "abc").matchesPort(1), false)
t("trailing separator in ports is not a wildcard", matcher("*", "*", "80;").matchesPort(443), false)
t("reversed range never matches", matcher("*", "*", "9000-8000").matchesPort(8500), false)

// hosts: ips, ranges, v6, domains
func dom(_ names: String...) -> [(name: String, chars: [Character])] { names.map { (name: $0, chars: Array($0)) } }
t("ip exact", matcher("*", "10.0.0.5", "*").matchesHost(ip: "10.0.0.5", domains: []), true)
t("ip wildcard octet", matcher("*", "192.168.1.*", "*").matchesHost(ip: "192.168.1.9", domains: []), true)
t("ip range", matcher("*", "10.0.0.1-10.0.0.9", "*").matchesHost(ip: "10.0.0.5", domains: []), true)
t("ip miss", matcher("*", "10.0.0.5", "*").matchesHost(ip: "10.0.0.6", domains: []), false)
t("ipv6 exact", matcher("*", "::1", "*").matchesHost(ip: "::1", domains: []), true)
t("ipv6 prefix wildcard", matcher("*", "2001:db8:*", "*").matchesHost(ip: "2001:db8::5", domains: []), true)
t("domain glob", matcher("*", "*.github.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("api.github.com")), true)
t("domain glob covers the apex", matcher("*", "*.github.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("github.com")), true)
t("domain miss", matcher("*", "*.gitlab.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("api.github.com")), false)
t("domain exact", matcher("*", "example.com", "*").matchesHost(ip: "1.1.1.1", domains: dom("example.com")), true)
t("list of ip and domain", matcher("*", "1.2.3.4;*.github.com", "*").matchesHost(ip: "9.9.9.9", domains: dom("api.github.com")), true)
t("domain rule without any known name", matcher("*", "*.github.com", "*").matchesHost(ip: "9.9.9.9", domains: []), false)
t("all hosts", matcher("*", "*", "*").matchesHost(ip: "9.9.9.9", domains: []), true)

print(fails == 0 ? "matcher tests: ALL PASS" : "matcher tests: \(fails) FAILED")
exit(fails == 0 ? 0 : 1)

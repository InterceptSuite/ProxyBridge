// Command line options and profile loading (CLIArguments.swift, CLIProfile.swift). Compiled as main.swift by run.sh.
import Foundation

var fails = 0
func t(_ name: String, _ ok: Bool) { if !ok { fails += 1; print("FAIL", name) } }
func opts(_ args: [String]) -> CLIOptions? { if case .run(let o) = CLIArguments.parse(["proxybridge"] + args) { return o }; return nil }
func err(_ args: [String]) -> String? { if case .failure(let m) = CLIArguments.parse(["proxybridge"] + args) { return m }; return nil }

// ---- GUI or CLI
t("no options is the GUI", !CLIArguments.isCLI(["/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge"]))
t("only the program name is the GUI", !CLIArguments.isCLI(["ProxyBridge"]))
t("empty arguments is the GUI", !CLIArguments.isCLI([]))
t("old Finder launch argument is the GUI", !CLIArguments.isCLI(["ProxyBridge", "-psn_0_12345"]))
t("Xcode debug arguments are the GUI", !CLIArguments.isCLI(["ProxyBridge", "-NSDocumentRevisionsDebugMode", "YES"]))
for flag in ["--cli", "--profile", "--verbose", "--version", "--update", "--list-profiles", "--help", "-h", "-?"] {
    t("\(flag) means the command line", CLIArguments.isCLI(["ProxyBridge", flag]))
}
t("--profile=name means the command line", CLIArguments.isCLI(["ProxyBridge", "--profile=work"]))
t("--verbose=2 means the command line", CLIArguments.isCLI(["ProxyBridge", "--verbose=2"]))
t("the program name itself is not an option", !CLIArguments.isCLI(["--profile"]))   // argv[0] is skipped

// ---- parsing
t("profile name", opts(["--profile", "work"])?.profile == "work")
t("profile from stdin", opts(["--profile", "-"])?.profile == "-")
t("profile with =", opts(["--profile=work"])?.profile == "work")
t("verbose default is 0", opts(["--profile", "w"])?.verbose == 0)
t("verbose 3", opts(["--profile", "w", "--verbose", "3"])?.verbose == 3)
t("verbose with =", opts(["--profile", "w", "--verbose=2"])?.verbose == 2)
t("verbose before profile", opts(["--verbose", "1", "--profile", "w"]) == CLIOptions(profile: "w", verbose: 1))
t("--cli is accepted and ignored", opts(["--cli", "--profile", "w"])?.profile == "w")
t("help alone", opts(["--help"])?.help == true)
t("-h alone", opts(["-h"])?.help == true)
t("version alone", opts(["--version"])?.version == true)
t("list-profiles alone", opts(["--list-profiles"])?.listProfiles == true)
t("update alone", opts(["--update"])?.update == true)
t("a profile name with spaces is one value", opts(["--profile", "My Work Profile"])?.profile == "My Work Profile")
t("no profile is an error", err([])?.contains("--profile is required") == true)
t("only --verbose is an error", err(["--verbose", "2"])?.contains("--profile is required") == true)
t("--profile without a value", err(["--profile"])?.contains("requires a value") == true)
t("--profile followed by another option", err(["--profile", "--verbose", "2"])?.contains("requires a value") == true)
t("--profile= is empty", err(["--profile="])?.contains("requires a profile name") == true)
t("verbose 4 is rejected", err(["--profile", "w", "--verbose", "4"])?.contains("0-3") == true)
t("verbose -1 is rejected", err(["--profile", "w", "--verbose", "-1"])?.contains("0-3") == true)
t("verbose abc is rejected", err(["--profile", "w", "--verbose", "abc"])?.contains("0-3") == true)
t("unknown option", err(["--profile", "w", "--nope"])?.contains("Unknown option '--nope'") == true)
t("usage documents every option", ["--profile", "--list-profiles", "--verbose", "--update", "--version", "--help", "Ctrl+C", "--profile -"].allSatisfy { CLIArguments.usage.contains($0) })

// ---- profiles
func json(_ o: Any) -> Data { try! JSONSerialization.data(withJSONObject: o) }
let proxyA: [String: Any] = ["id": "p1", "name": "a", "type": "socks5", "host": "127.0.0.1", "port": 1080, "sendDomain": false]
let proxyB: [String: Any] = ["id": "p2", "type": "http", "host": "10.0.0.2", "port": 8080, "username": "u", "password": "pw"]   // no name, no sendDomain
let rule1: [String: Any] = ["processNames": "curl", "targetHosts": "*", "targetPorts": "*", "protocol": "TCP", "action": "p1", "enabled": true]
let rule2: [String: Any] = ["processNames": "nc", "targetHosts": "*", "targetPorts": "*", "protocol": "UDP", "action": "BLOCK", "enabled": true]
let exported = json(["name": "work", "trafficLoggingEnabled": true, "proxyConfigs": [proxyA, proxyB], "proxyRules": [rule1, rule2]] as [String: Any])

let p = try! CLIProfileLoader.parse(json: exported)
t("exported profile: name", p.name == "work")
t("exported profile: two proxies", p.proxies.count == 2)
t("exported profile: proxy fields", p.proxies[0].host == "127.0.0.1" && p.proxies[0].port == 1080 && p.proxies[0].type == "socks5")
t("exported profile: sendDomain false is kept", p.proxies[0].sendDomain == false)
t("exported profile: missing sendDomain defaults to true", p.proxies[1].sendDomain == true)
t("exported profile: credentials", p.proxies[1].username == "u" && p.proxies[1].password == "pw")
t("exported profile: missing name is empty", p.proxies[1].name == "")
t("exported profile: rules kept as saved", p.rules.count == 2 && (p.rules[0]["action"] as? String) == "p1")
t("label", p.proxies[0].label == "SOCKS5 127.0.0.1:1080")
t("not json is an error", (try? CLIProfileLoader.parse(json: Data("nope".utf8))) == nil)
do { _ = try CLIProfileLoader.parse(json: json(["ProxyConfigs": [], "ProxyRules": []] as [String: Any])); t("windows layout is refused", false) }
catch let e as CLIProfileError { t("windows layout is refused with an explanation", e.message.contains("Windows")) } catch { t("windows layout error type", false) }
do { _ = try CLIProfileLoader.parse(json: json(["proxyConfigs": [["id": "x"]]] as [String: Any])); t("proxy without host is refused", false) }
catch { t("proxy without host is refused", true) }
t("profile with only rules is fine", (try? CLIProfileLoader.parse(json: json(["proxyRules": [rule2]] as [String: Any])))?.proxies.isEmpty == true)

// saved profiles: the active one is in the working keys, the others in snapshots
let store: [String: Any] = [
    "profiles": ["Default", "work"], "activeProfile": "Default",
    "proxyConfigs": json([proxyA]), "proxyRules": [rule1],
    "profile.work.proxyConfigs": json([proxyB]), "profile.work.proxyRules": [rule2, rule1],
]
let read: CLIProfileLoader.Reader = { store[$0] }
let active = try! CLIProfileLoader.saved(named: "Default", read: read)
t("active profile reads the working keys", active.proxies.count == 1 && active.proxies[0].id == "p1" && active.rules.count == 1)
let other = try! CLIProfileLoader.saved(named: "work", read: read)
t("other profile reads its snapshot", other.proxies[0].id == "p2" && other.rules.count == 2)
do { _ = try CLIProfileLoader.saved(named: "nope", read: read); t("unknown profile is an error", false) }
catch let e as CLIProfileError { t("unknown profile lists what exists", e.message.contains("Default, work") && e.message.contains("--list-profiles")) } catch { t("unknown profile error type", false) }
do { _ = try CLIProfileLoader.saved(named: "x", read: { _ in nil }); t("no profiles saved is an error", false) }
catch let e as CLIProfileError { t("no profiles saved says so", e.message.contains("none saved yet")) } catch { t("error type", false) }
let names = CLIProfileLoader.savedNames(read: read)
t("saved names and active", names.names == ["Default", "work"] && names.active == "Default")
t("an empty profile has empty lists", (try? CLIProfileLoader.saved(named: "e", read: { ["profiles": ["e"]][$0] }))?.proxies.isEmpty == true)

// ---- warnings
let ok = CLIProfile(name: "w", proxies: [try! JSONDecoder().decode(CLIProxy.self, from: json(proxyA))], rules: [rule1, rule2])
t("a good profile has no warnings", CLIProfileLoader.warnings(for: ok).isEmpty)
var dangling = ok; dangling.rules.append(["action": "gone"])
t("a rule pointing at a missing proxy warns", CLIProfileLoader.warnings(for: dangling).contains { $0.contains("rule 3") && $0.contains("go direct") })
t("DIRECT and BLOCK never warn", CLIProfileLoader.warnings(for: CLIProfile(name: "w", proxies: [], rules: [["action": "DIRECT"], ["action": "BLOCK"]])).isEmpty)
t("a rule with no action counts as DIRECT", CLIProfileLoader.warnings(for: CLIProfile(name: "w", proxies: [], rules: [[:]])).isEmpty)
t("no rules warns", CLIProfileLoader.warnings(for: CLIProfile(name: "w", proxies: [], rules: [])).contains { $0.contains("no rules") })
// ---- errors (these stop the run)
func profile(proxies: [[String: Any]] = [], rules: [[String: Any]] = []) -> CLIProfile {
    CLIProfile(name: "w", proxies: proxies.map { try! JSONDecoder().decode(CLIProxy.self, from: json($0)) }, rules: rules)
}
t("a good profile has no errors", CLIProfileLoader.errors(for: ok).isEmpty)
t("port 0 is an error", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "socks5", "host": "h", "port": 0]])).contains { $0.contains("port 0") })
t("port 65536 is an error", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "socks5", "host": "h", "port": 65536]])).contains { $0.contains("65536") })
t("port 65535 is fine", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "http", "host": "h", "port": 65535]])).isEmpty)
t("an empty host is an error", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "http", "host": "  ", "port": 80]])).contains { $0.contains("no host") })
t("an unsupported proxy type is an error", CLIProfileLoader.errors(for: profile(proxies: [["id": "z", "type": "ftp", "host": "h", "port": 1]])).contains { $0.contains("socks5 or http") })
t("proxy types are case-insensitive", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "SOCKS5", "host": "h", "port": 1]])).isEmpty)
t("duplicate proxy ids are an error", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "http", "host": "h", "port": 1], ["id": "a", "type": "http", "host": "h2", "port": 2]])).contains { $0.contains("same id") })
let longPw = String(repeating: "x", count: 256)
t("a 256 byte SOCKS5 password is an error", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "socks5", "host": "h", "port": 1, "password": longPw]])).contains { $0.contains("255 bytes") })
t("a long password is fine for an http proxy", CLIProfileLoader.errors(for: profile(proxies: [["id": "a", "type": "http", "host": "h", "port": 1, "password": longPw]])).isEmpty)
t("an unknown rule protocol is an error", CLIProfileLoader.errors(for: profile(rules: [["protocol": "ICMP", "action": "BLOCK"]])).contains { $0.contains("rule 1") && $0.contains("TCP, UDP or BOTH") })
t("a rule without a protocol means BOTH", CLIProfileLoader.errors(for: profile(rules: [["action": "BLOCK"]])).isEmpty)
t("too many rules is an error", CLIProfileLoader.errors(for: profile(rules: Array(repeating: ["action": "BLOCK"], count: CLIProfileLoader.maxRules + 1))).contains { $0.contains("limit") })
t("exactly the maximum number of rules is fine", CLIProfileLoader.errors(for: profile(rules: Array(repeating: ["action": "BLOCK"], count: CLIProfileLoader.maxRules))).isEmpty)
t("too many proxies is an error", CLIProfileLoader.errors(for: profile(proxies: (0...CLIProfileLoader.maxProxies).map { ["id": "p\($0)", "type": "http", "host": "h", "port": 1] })).contains { $0.contains("limit") })

// ---- terminal safety
t("plain text is unchanged", CLIText.safe("curl -> example.com:443") == "curl -> example.com:443")
t("unicode is unchanged", CLIText.safe("caf\u{e9} \u{1F600} \u{4E2D}") == "caf\u{e9} \u{1F600} \u{4E2D}")
t("an escape sequence is defanged", !CLIText.safe("\u{1b}[2J\u{1b}[31mred").contains("\u{1b}"))
t("escape text becomes visible, not lost", CLIText.safe("a\u{1b}[2Jb") == "a?[2Jb")
t("newline and carriage return are replaced", CLIText.safe("a\nb\rc") == "a?b?c")
t("backspace and bell are replaced", CLIText.safe("a\u{8}b\u{7}") == "a?b?")
t("C1 control characters are replaced", CLIText.safe("a\u{9b}b") == "a?b")
t("DEL is replaced", CLIText.safe("a\u{7f}b") == "a?b")
t("empty stays empty", CLIText.safe("") == "")

print(fails == 0 ? "cli tests: ALL PASS" : "cli tests: \(fails) FAILED")
exit(fails == 0 ? 0 : 1)

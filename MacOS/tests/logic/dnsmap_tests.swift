// DNSMapStore: lookups, newest-first, the 5 minute name age, caps, hostname safety. Compiled as main.swift by run.sh.
import Foundation

var fails = 0
func t(_ name: String, _ ok: Bool) { if !ok { fails += 1; print("FAIL", name) } }
let s = DNSMapStore.shared
s.clear()

s.record(domain: "A.Example.com", ips: ["1.1.1.1", "2606::1"], now: 100)
t("lookup is lowercased", s.domains(forIP: "1.1.1.1") == ["a.example.com"])
t("ipv6 key", s.domains(forIP: "2606::1") == ["a.example.com"])
s.record(domain: "b.example.com", ips: ["1.1.1.1"], now: 110)
t("newest first", s.domains(forIP: "1.1.1.1") == ["b.example.com", "a.example.com"])
s.record(domain: "a.example.com", ips: ["1.1.1.1"], now: 120)
t("seen again becomes newest without a duplicate", s.domains(forIP: "1.1.1.1") == ["a.example.com", "b.example.com"])
for i in 0..<20 { s.record(domain: "d\(i).test", ips: ["9.9.9.9"], now: 200) }
t("at most 8 names per ip, newest kept", s.domains(forIP: "9.9.9.9").count == 8 && s.domains(forIP: "9.9.9.9").first == "d19.test")
for i in 0..<3000 { s.record(domain: "x\(i).test", ips: ["10.\(i / 250).\(i % 250).1"], now: 300) }
t("map stays bounded, oldest evicted", s.domains(forIP: "10.0.0.1").isEmpty)
t("newest entries kept", s.domains(forIP: "10.11.249.1") == ["x2999.test"])
s.clear()
t("clear empties the map", s.domains(forIP: "1.1.1.1").isEmpty)

// the name handed to a proxy (Let proxy resolve DNS)
s.record(domain: "a.example.com", ips: ["1.1.1.1"], now: 100)
s.record(domain: "b.example.com", ips: ["1.1.1.1"], now: 110)
t("newest name wins", s.latestDomain(forIP: "1.1.1.1", maxAge: 300, now: 120) == "b.example.com")
t("still good at exactly 300 seconds", s.latestDomain(forIP: "1.1.1.1", maxAge: 300, now: 410) == "b.example.com")
t("expired after 300 seconds", s.latestDomain(forIP: "1.1.1.1", maxAge: 300, now: 411) == nil)
s.record(domain: "a.example.com", ips: ["1.1.1.1"], now: 500)
t("a fresh answer refreshes the age", s.latestDomain(forIP: "1.1.1.1", maxAge: 300, now: 600) == "a.example.com")
t("unknown address gives nil so the caller sends the ip", s.latestDomain(forIP: "8.8.4.4", maxAge: 300, now: 600) == nil)

// names come out of DNS packets, only plain host names may reach a proxy
let good = ["example.com", "a-b.c_d.example.org", "xn--bcher-kva.example", "localhost", "a"]
let bad = ["", "exa mple.com", "example.com\r\nHost: evil", "exam\u{0}ple.com", "ex\u{e9}ample.com", ".example.com", "example.com.",
           "1.2.3.4", "::1", "example.com:443", "a/b.com", "a@b.com", String(repeating: "a", count: 254)]
for g in good { t("safe name: \(g)", DNSMapStore.isSafeHostname(g)) }
for b in bad { t("unsafe name rejected: \(b.debugDescription.prefix(28))", !DNSMapStore.isSafeHostname(b)) }
s.record(domain: "bad name.com", ips: ["5.5.5.5"], now: 1000)
t("an unsafe newest name is never returned", s.latestDomain(forIP: "5.5.5.5", maxAge: 300, now: 1001) == nil)
s.record(domain: "1.2.3.4", ips: ["1.2.3.4"], now: 1000)
t("an ip literal is not a name", s.latestDomain(forIP: "1.2.3.4", maxAge: 300, now: 1001) == nil)

// several threads writing and reading at once
let group = DispatchGroup()
for w in 0..<8 {
    DispatchQueue.global().async(group: group) {
        for i in 0..<5000 { s.record(domain: "c\(w).test", ips: ["7.\(w).\(i % 200).1"]); _ = s.domains(forIP: "7.\(w).1.1") }
    }
}
group.wait()

print(fails == 0 ? "dns map tests: ALL PASS" : "dns map tests: \(fails) FAILED")
exit(fails == 0 ? 0 : 1)

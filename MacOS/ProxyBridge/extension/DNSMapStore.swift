import Foundation
import Network

// Shared IP -> domain map, filled by the DNS proxy and read by the transparent
// proxy. Both providers are loaded into the same extension process, so a plain
// in-memory map is enough. It used to be mirrored to a json file in the app group
// container, which meant a full serialize and write on every new address, a stat
// on every connection, a re-parse on every change, and a list of the sites that
// were visited sitting on disk.
final class DNSMapStore {
    static let shared = DNSMapStore()

    private struct Entry {
        let name: String
        var seen: TimeInterval   // system uptime when a DNS answer last mentioned it
    }

    private let lock = NSLock()
    private var map: [String: [Entry]] = [:]    // ip -> domains, newest last
    private var order: [String] = []            // ips in insertion order, for eviction
    private let maxEntries = 1024
    private let maxDomainsPerIP = 8             // a cdn address can serve many names

    private init() {}

    // wipe the map. called on start/stop. it also removes the file older versions
    // wrote, so an upgrade doesn't leave that browsing history behind.
    func clear() {
        lock.lock()
        map.removeAll()
        order.removeAll()
        lock.unlock()
        removeLegacyFile()
    }

    // DNS proxy: remember that these IPs resolved for this domain
    func record(domain: String, ips: [String], now: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        let name = domain.lowercased()
        guard !name.isEmpty, !ips.isEmpty else { return }

        lock.lock()
        for ip in ips {
            if map[ip] == nil {
                map[ip] = []
                order.append(ip)
                if order.count > maxEntries {
                    // drop a batch at once so the O(n) removal isn't paid per insert
                    let overflow = order.count - maxEntries + 64
                    for evicted in order.prefix(overflow) { map[evicted] = nil }
                    order.removeFirst(min(overflow, order.count))
                }
            }
            var domains = map[ip] ?? []
            if let existing = domains.firstIndex(where: { $0.name == name }) {
                // seen again, make it the newest and refresh its age
                domains.remove(at: existing)
            } else if domains.count >= maxDomainsPerIP {
                domains.removeFirst()
            }
            domains.append(Entry(name: name, seen: now))
            map[ip] = domains
        }
        lock.unlock()
    }

    // transparent proxy: domains that resolved to this ip, newest first
    func domains(forIP ip: String) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        guard let domains = map[ip] else { return [] }
        return domains.reversed().map { $0.name }
    }

    // the name a proxy should get instead of the ip ("let proxy resolve DNS"). the
    // newest name for this address, only if a DNS answer mentioned it within maxAge
    // seconds (the windows app uses the same 5 minutes), and only if it is a
    // plain host name that is safe to put in a CONNECT line
    func latestDomain(forIP ip: String, maxAge: TimeInterval, now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let newest = map[ip]?.last, now - newest.seen <= maxAge,
              DNSMapStore.isSafeHostname(newest.name) else { return nil }
        return newest.name
    }

    // names come straight out of DNS packets, so they can hold any byte. only
    // letters, digits, '.', '-' and '_' go to a proxy (a space or CRLF would
    // inject into the http CONNECT request), and an ip literal isn't a name
    static func isSafeHostname(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 253, !name.hasPrefix("."), !name.hasSuffix(".") else { return false }
        for byte in name.utf8 {
            switch byte {
            case 0x30...0x39, 0x61...0x7A, 0x41...0x5A, 0x2E, 0x2D, 0x5F: continue
            default: return false
            }
        }
        if IPv4Address(name) != nil || IPv6Address(name) != nil { return false }
        return true
    }

    private func removeLegacyFile() {
        guard let url = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.interceptsuite.ProxyBridge")?
            .appendingPathComponent("dnsmap.json") else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

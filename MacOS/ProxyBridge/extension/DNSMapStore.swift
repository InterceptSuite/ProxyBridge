import Foundation

// Shared IP -> domain map, filled by the DNS proxy and read by the transparent
// proxy. Both providers are loaded into the same extension process, so a plain
// in-memory map is enough. It used to be mirrored to a json file in the app group
// container, which meant a full serialize and write on every new address, a stat
// on every connection, a re-parse on every change, and a list of the sites that
// were visited sitting on disk.
final class DNSMapStore {
    static let shared = DNSMapStore()

    private let lock = NSLock()
    private var map: [String: [String]] = [:]   // ip -> domains, newest last
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
    func record(domain: String, ips: [String]) {
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
            if let existing = domains.firstIndex(of: name) {
                // seen again, make it the newest
                domains.remove(at: existing)
            } else if domains.count >= maxDomainsPerIP {
                domains.removeFirst()
            }
            domains.append(name)
            map[ip] = domains
        }
        lock.unlock()
    }

    // transparent proxy: domains that resolved to this ip, newest first
    func domains(forIP ip: String) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        guard let domains = map[ip] else { return [] }
        return domains.reversed()
    }

    private func removeLegacyFile() {
        guard let url = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.interceptsuite.ProxyBridge")?
            .appendingPathComponent("dnsmap.json") else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

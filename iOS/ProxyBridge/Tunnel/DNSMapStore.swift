import Foundation

/// Remembers which names resolved to which IP addresses. A rule written for a domain can then match a connection
/// that only carries an address, and a proxy can be given the name instead of the address.
final class DNSMapStore {
    static let shared = DNSMapStore()

    private struct Entry {
        let name: String
        var seen: TimeInterval
    }

    private let lock = NSLock()
    private var entriesByIP: [String: [Entry]] = [:]   // newest last
    private var insertionOrder: [String] = []
    private let capacity = 2048
    private let namesPerIP = 8   // a CDN address can serve many names

    func record(domain: String, ips: [String], now: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        let name = domain.lowercased()
        guard !name.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        for ip in ips {
            if entriesByIP[ip] == nil {
                insertionOrder.append(ip)
                if insertionOrder.count > capacity {
                    entriesByIP[insertionOrder.removeFirst()] = nil
                }
            }
            var entries = entriesByIP[ip] ?? []
            if let existing = entries.firstIndex(where: { $0.name == name }) {
                entries.remove(at: existing)
            } else if entries.count >= namesPerIP {
                entries.removeFirst()
            }
            entries.append(Entry(name: name, seen: now))
            entriesByIP[ip] = entries
        }
    }

    /// Every name that resolved to the address, newest first.
    func domains(forIP ip: String) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return (entriesByIP[ip] ?? []).reversed().map(\.name)
    }

    /// The name to give a proxy instead of the address: the newest one, if a DNS answer mentioned it within
    /// `maxAge` seconds and it is safe to put in a proxy request.
    func hostname(forIP ip: String, maxAge: TimeInterval = 300,
                  now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let newest = entriesByIP[ip]?.last, now - newest.seen <= maxAge,
              Self.isSafeHostname(newest.name) else { return nil }
        return newest.name
    }

    /// Names come out of DNS packets and can hold any byte. Only letters, digits, '.', '-' and '_' are passed on,
    /// because a space or a line break would end up inside an HTTP CONNECT request.
    static func isSafeHostname(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 253, !name.hasPrefix("."), !name.hasSuffix(".") else { return false }
        let allowed = name.utf8.allSatisfy {
            switch $0 {
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2E, 0x2D, 0x5F: return true
            default: return false
            }
        }
        return allowed && RuleMatch.ipToBytes(name) == nil
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        entriesByIP.removeAll()
        insertionOrder.removeAll()
    }
}

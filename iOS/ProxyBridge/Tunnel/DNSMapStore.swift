import Foundation

/// Remembers which names resolved to which IP addresses, so a rule written for a domain can match a connection
/// that only carries an address. The oldest entries are dropped first.
final class DNSMapStore {
    static let shared = DNSMapStore()

    private let lock = NSLock()
    private var domainsByIP: [String: Set<String>] = [:]
    private var insertionOrder: [String] = []
    private let capacity = 2048

    func record(domain: String, ips: [String]) {
        let name = domain.lowercased()
        guard !name.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        for ip in ips {
            if domainsByIP[ip] == nil {
                insertionOrder.append(ip)
                if insertionOrder.count > capacity {
                    domainsByIP[insertionOrder.removeFirst()] = nil
                }
            }
            domainsByIP[ip, default: []].insert(name)
        }
    }

    func domains(forIP ip: String) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return Array(domainsByIP[ip] ?? [])
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        domainsByIP.removeAll()
        insertionOrder.removeAll()
    }
}

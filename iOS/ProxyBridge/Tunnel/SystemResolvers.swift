import Foundation

enum SystemResolvers {
    private static let fallback = ["1.1.1.1", "8.8.8.8"]

    /// DNS servers of the current network. Read before the tunnel is up, while they are still the real ones.
    static func current() -> [String] {
        var buffer = [CChar](repeating: 0, count: 512)
        guard system_dns_servers(&buffer, buffer.count) > 0 else { return fallback }
        let servers = String(cString: buffer).split(separator: "\n").map(String.init)
        return servers.isEmpty ? fallback : servers
    }
}

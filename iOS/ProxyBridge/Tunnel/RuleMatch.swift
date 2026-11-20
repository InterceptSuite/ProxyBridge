import Foundation

enum RuleMatch {
    /// Wildcard match where `*` stands for any run of characters.
    static func glob(_ pattern: String, _ text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0, star = -1, mark = 0
        while ti < t.count {
            if pi < p.count, p[pi] == "*" {
                star = pi
                mark = ti
                pi += 1
            } else if pi < p.count, p[pi] == t[ti] {
                pi += 1
                ti += 1
            } else if star != -1 {
                pi = star + 1
                mark += 1
                ti = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }

    /// Raw bytes of an IPv4 (4 bytes) or IPv6 (16 bytes) literal.
    static func ipToBytes(_ text: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            return withUnsafeBytes(of: &v4) { Array($0) }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { Array($0) }
        }
        return nil
    }

    static func ipString(_ bytes: [UInt8]) -> String {
        switch bytes.count {
        case 4:
            return bytes.map(String.init).joined(separator: ".")
        case 16:
            var addr = in6_addr()
            withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: bytes) }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &addr, &buffer, socklen_t(buffer.count)) != nil else { return "" }
            return String(cString: buffer)
        default:
            return ""
        }
    }

    /// True when the first `bits` bits of both addresses are equal.
    static func prefixEqual(_ a: [UInt8], _ b: [UInt8], bits: Int) -> Bool {
        guard a.count == b.count, bits >= 0, bits <= a.count * 8 else { return false }
        let whole = bits / 8
        guard a[..<whole] == b[..<whole] else { return false }
        let rest = bits % 8
        guard rest > 0 else { return true }
        let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - rest))
        return a[whole] & mask == b[whole] & mask
    }
}

import Foundation

/// Reads the question name and the A and AAAA answers of a DNS response. Every offset is bounds checked
/// because the data comes from the network.
enum DNSParser {
    struct Answer {
        let domain: String
        let ips: [String]
    }

    private static let typeA = 1
    private static let typeAAAA = 28

    static func parse(_ b: [UInt8]) -> Answer? {
        guard b.count >= 12 else { return nil }
        let questions = Int(b[4]) << 8 | Int(b[5])
        let answers = Int(b[6]) << 8 | Int(b[7])
        guard questions >= 1, let (name, afterName) = readName(b, at: 12), !name.isEmpty else { return nil }

        var i = afterName + 4
        for _ in 1..<questions {
            guard let next = skipName(b, at: i) else { return nil }
            i = next + 4
        }

        var ips: [String] = []
        for _ in 0..<answers {
            guard let afterOwner = skipName(b, at: i), afterOwner + 10 <= b.count else { break }
            let type = Int(b[afterOwner]) << 8 | Int(b[afterOwner + 1])
            let length = Int(b[afterOwner + 8]) << 8 | Int(b[afterOwner + 9])
            let start = afterOwner + 10
            guard start + length <= b.count else { break }
            if (type == typeA && length == 4) || (type == typeAAAA && length == 16) {
                ips.append(RuleMatch.ipString(Array(b[start..<start + length])))
            }
            i = start + length
        }
        return Answer(domain: name, ips: ips)
    }

    /// Reads a possibly compressed name. Returns the name and the offset right after it.
    private static func readName(_ b: [UInt8], at start: Int) -> (String, Int)? {
        var labels: [String] = []
        var i = start
        var resume: Int?
        var jumps = 0
        while i < b.count {
            let length = Int(b[i])
            if length == 0 {
                return (labels.joined(separator: "."), resume ?? i + 1)
            }
            if length & 0xC0 == 0xC0 {
                guard i + 1 < b.count else { return nil }
                resume = resume ?? i + 2
                i = (length & 0x3F) << 8 | Int(b[i + 1])
                jumps += 1
                if jumps > 32 { return nil }
                continue
            }
            guard i + 1 + length <= b.count else { return nil }
            labels.append(String(decoding: b[(i + 1)..<(i + 1 + length)], as: UTF8.self))
            i += 1 + length
        }
        return nil
    }

    private static func skipName(_ b: [UInt8], at start: Int) -> Int? {
        var i = start
        while i < b.count {
            let length = Int(b[i])
            if length == 0 { return i + 1 }
            if length & 0xC0 == 0xC0 { return i + 2 }
            i += 1 + length
        }
        return nil
    }
}

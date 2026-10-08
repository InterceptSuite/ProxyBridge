import NetworkExtension

// Intercepts system DNS, forwards each query to the real resolver, and records
// the resulting IP -> domain mapping so the transparent proxy can match rules by
// domain. DoH/DoT that an app does itself is not visible here (by design).
class DNSProxyProvider: NEDNSProxyProvider {
    // one udp session per (flow, resolver), reused for every query on that flow.
    // the system resolver keeps a handful of long-lived flows, so this replaces a
    // socket per query with a few sockets total
    private final class FlowSessions {
        private var sessions: [String: NWUDPSession] = [:]
        private let lock = NSLock()
        private var closed = false

        func session(for server: NWHostEndpoint, create: () -> NWUDPSession, onNew: (NWUDPSession) -> Void) -> NWUDPSession? {
            let key = "\(server.hostname):\(server.port)"
            lock.lock()
            defer { lock.unlock() }
            if closed { return nil }
            if let existing = sessions[key], existing.state == .ready || existing.state == .preparing || existing.state == .waiting {
                return existing
            }
            sessions[key]?.cancel()
            let fresh = create()
            sessions[key] = fresh
            onNew(fresh)
            return fresh
        }

        func closeAll() {
            lock.lock()
            closed = true
            let all = sessions.values
            sessions.removeAll()
            lock.unlock()
            all.forEach { $0.cancel() }
        }
    }

    private var flowStates: [ObjectIdentifier: FlowSessions] = [:]
    private let statesLock = NSLock()

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        // start with a clean map so old browsing domains don't linger on disk
        DNSMapStore.shared.clear()
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        statesLock.lock()
        let all = Array(flowStates.values)
        flowStates.removeAll()
        statesLock.unlock()
        all.forEach { $0.closeAll() }
        DNSMapStore.shared.clear()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // only proxy udp dns, let tcp dns (large responses) pass through untouched
        guard let udp = flow as? NEAppProxyUDPFlow else { return false }
        udp.open(withLocalEndpoint: nil) { [weak self] error in
            guard error == nil, let self = self else {
                udp.closeReadWithError(error)
                udp.closeWriteWithError(error)
                return
            }
            let state = FlowSessions()
            self.statesLock.lock()
            self.flowStates[ObjectIdentifier(udp)] = state
            self.statesLock.unlock()
            self.readQueries(udp, state)
        }
        return true
    }

    private func finish(_ flow: NEAppProxyUDPFlow, _ state: FlowSessions) {
        statesLock.lock()
        flowStates.removeValue(forKey: ObjectIdentifier(flow))
        statesLock.unlock()
        state.closeAll()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
    }

    private func readQueries(_ flow: NEAppProxyUDPFlow, _ state: FlowSessions) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            guard error == nil, let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else {
                self.finish(flow, state)
                return
            }

            for i in 0..<min(datagrams.count, endpoints.count) {
                guard let server = endpoints[i] as? NWHostEndpoint else { continue }
                self.forward(query: datagrams[i], to: server, on: flow, state: state)
            }

            self.readQueries(flow, state)
        }
    }

    // forward one query to its resolver over the flow's shared session
    private func forward(query: Data, to server: NWHostEndpoint, on flow: NEAppProxyUDPFlow, state: FlowSessions) {
        let session = state.session(for: server, create: { createUDPSession(to: server, from: nil) }, onNew: { fresh in
            // replies are parsed for the ip -> domain map, then handed back to the app
            fresh.setReadHandler({ responses, _ in
                guard let responses = responses else { return }
                for response in responses {
                    if let parsed = DNSParser.parse(response) {
                        DNSMapStore.shared.record(domain: parsed.domain, ips: parsed.ips)
                    }
                }
                flow.writeDatagrams(responses, sentBy: [NWEndpoint](repeating: server, count: responses.count)) { _ in }
            }, maxDatagrams: 16)
        })
        session?.writeDatagram(query) { _ in }
    }
}

// Minimal DNS message parser: pulls the queried name and its A/AAAA answers.
enum DNSParser {
    static func parse(_ data: Data) -> (domain: String, ips: [String])? {
        let b = [UInt8](data)
        guard b.count >= 12 else { return nil }

        let qdCount = Int(b[4]) << 8 | Int(b[5])
        let anCount = Int(b[6]) << 8 | Int(b[7])
        guard qdCount >= 1 else { return nil }

        var i = 12
        guard let qname = readName(b, &i), i + 4 <= b.count else { return nil }
        i += 4 // QTYPE + QCLASS

        // skip any extra questions (rare)
        if qdCount > 1 {
            for _ in 1..<qdCount {
                guard skipName(b, &i), i + 4 <= b.count else { return nil }
                i += 4
            }
        }

        var ips: [String] = []
        for _ in 0..<anCount {
            guard skipName(b, &i), i + 10 <= b.count else { break }
            let type = Int(b[i]) << 8 | Int(b[i + 1])
            let rdlen = Int(b[i + 8]) << 8 | Int(b[i + 9])
            i += 10
            guard i + rdlen <= b.count else { break }

            if type == 1, rdlen == 4 {
                ips.append("\(b[i]).\(b[i + 1]).\(b[i + 2]).\(b[i + 3])")
            } else if type == 28, rdlen == 16 {
                var parts: [String] = []
                for k in stride(from: 0, to: 16, by: 2) {
                    parts.append(String(format: "%x", Int(b[i + k]) << 8 | Int(b[i + k + 1])))
                }
                ips.append(parts.joined(separator: ":"))
            }
            i += rdlen
        }

        return ips.isEmpty ? nil : (qname.lowercased(), ips)
    }

    // reads a name into a string, following compression pointers
    private static func readName(_ b: [UInt8], _ i: inout Int) -> String? {
        var labels: [String] = []
        var j = i
        var jumped = false
        var hops = 0
        while j < b.count {
            hops += 1
            if hops > 128 { return nil }
            let len = Int(b[j])
            if len == 0 {
                if !jumped { i = j + 1 }
                break
            }
            if len & 0xC0 == 0xC0 {
                guard j + 1 < b.count else { return nil }
                if !jumped { i = j + 2 }
                jumped = true
                j = (len & 0x3F) << 8 | Int(b[j + 1])
                continue
            }
            guard j + 1 + len <= b.count else { return nil }
            labels.append(String(bytes: b[(j + 1)..<(j + 1 + len)], encoding: .utf8) ?? "")
            j += 1 + len
        }
        return labels.joined(separator: ".")
    }

    // advances the offset past a name without decoding it
    private static func skipName(_ b: [UInt8], _ i: inout Int) -> Bool {
        var j = i
        while j < b.count {
            let len = Int(b[j])
            if len == 0 { i = j + 1; return true }
            if len & 0xC0 == 0xC0 { i = j + 2; return true }
            j += 1 + len
        }
        return false
    }
}

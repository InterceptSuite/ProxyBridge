import NetworkExtension
import Foundation

enum RuleProtocol: String, Codable {
    case tcp = "TCP"
    case udp = "UDP"
    case both = "BOTH"
}

struct ProxyRule: Codable {
    var ruleId: UInt32
    let processNames: String
    let targetHosts: String
    let targetPorts: String
    let ruleProtocol: RuleProtocol
    let action: String  // "DIRECT", "BLOCK", or a proxy config UUID
    var enabled: Bool

    enum CodingKeys: String, CodingKey {
        case ruleId
        case processNames
        case targetHosts
        case targetPorts
        case ruleProtocol
        case action = "ruleAction"
        case enabled
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ruleId = try container.decodeIfPresent(UInt32.self, forKey: .ruleId) ?? 0
        self.processNames = try container.decode(String.self, forKey: .processNames)
        self.targetHosts = try container.decode(String.self, forKey: .targetHosts)
        self.targetPorts = try container.decode(String.self, forKey: .targetPorts)
        self.ruleProtocol = try container.decode(RuleProtocol.self, forKey: .ruleProtocol)
        self.action = try container.decode(String.self, forKey: .action)
        self.enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }

    init(ruleId: UInt32, processNames: String, targetHosts: String, targetPorts: String, ruleProtocol: RuleProtocol, action: String, enabled: Bool) {
        self.ruleId = ruleId
        self.processNames = processNames
        self.targetHosts = targetHosts
        self.targetPorts = targetPorts
        self.ruleProtocol = ruleProtocol
        self.action = action
        self.enabled = enabled
    }
    
    func matchesProcess(bundleId: String, processName: String?) -> Bool {
        if Self.matchProcessList(processNames, processPath: bundleId) {
            return true
        }
        
        if let procName = processName {
            if Self.matchProcessList(processNames, processPath: procName) {
                return true
            }
        }
        
        return false
    }
    
    func matchesIP(_ ipString: String) -> Bool {
        return Self.matchIPList(targetHosts, ipString: ipString)
    }

    // matches targetHosts against the destination ip and any domains that
    // resolved to it (from the dns proxy). a pattern can be an ip/range or a
    // domain like *.github.com
    func matchesHost(ip: String, domains: [String]) -> Bool {
        if targetHosts.isEmpty || targetHosts == "*" { return true }
        for raw in targetHosts.components(separatedBy: ";") {
            let pattern = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if pattern.isEmpty { continue }
            if Self.matchIPPattern(pattern, ipString: ip) { return true }

            let lowered = pattern.lowercased()
            // *.example.com also covers the apex example.com, which is what users expect
            let apex = lowered.hasPrefix("*.") ? String(lowered.dropFirst(2)) : nil
            for domain in domains {
                if Self.globMatch(lowered, domain) { return true }
                if let apex = apex, domain == apex { return true }
            }
        }
        return false
    }


    func matchesPort(_ port: UInt16) -> Bool {
        return Self.matchPortList(targetPorts, port: port)
    }
    
    private static func matchProcessList(_ processList: String, processPath: String) -> Bool {
        if processList.isEmpty || processList == "*" {
            return true
        }
        
        let filename = (processPath as NSString).lastPathComponent
        let patterns = processList.components(separatedBy: CharacterSet(charactersIn: ",;"))
        
        for pattern in patterns {
            let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            if matchProcessPattern(trimmed, processPath: processPath, filename: filename) {
                return true
            }
        }
        return false
    }
    
    private static func matchProcessPattern(_ pattern: String, processPath: String, filename: String) -> Bool {
        if pattern.isEmpty || pattern == "*" {
            return true
        }

        let isFullPathPattern = pattern.contains("/") || pattern.contains("\\")
        let matchTarget = isFullPathPattern ? processPath : filename
        return globMatch(pattern.lowercased(), matchTarget.lowercased())
    }

    // wildcard match supporting any number of "*", e.g. *chrome*, com.*.browser, curl*
    private static func globMatch(_ pattern: String, _ text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0, star = -1, mark = 0
        while ti < t.count {
            if pi < p.count, p[pi] == t[ti] {
                pi += 1; ti += 1
            } else if pi < p.count, p[pi] == "*" {
                star = pi; mark = ti; pi += 1
            } else if star != -1 {
                pi = star + 1; mark += 1; ti = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
    
    private static func matchIPList(_ ipList: String, ipString: String) -> Bool {
        if ipList.isEmpty || ipList == "*" {
            return true
        }
        
        let patterns = ipList.components(separatedBy: ";")
        for pattern in patterns {
            let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            if matchIPPattern(trimmed, ipString: ipString) {
                return true
            }
        }
        return false
    }
    
    // raw bytes of a v4 (4) or v6 (16) address, nil if not an ip literal
    private static func ipToBytes(_ ipString: String) -> [UInt8]? {
        if let v4 = IPv4Address(ipString) { return Array(v4.rawValue) }
        if let v6 = IPv6Address(ipString) { return Array(v6.rawValue) }
        return nil
    }

    private static func compareBytes(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for i in 0..<min(a.count, b.count) where a[i] != b[i] {
            return a[i] < b[i] ? -1 : 1
        }
        return 0
    }

    // full 8 hextet form of a v6 address, e.g. ["2001","db8","0",...]
    private static func expandIPv6(_ ipString: String) -> [String]? {
        guard let v6 = IPv6Address(ipString) else { return nil }
        let bytes = Array(v6.rawValue)
        var groups: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            let value = (UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1])
            groups.append(String(format: "%x", value))
        }
        return groups
    }

    private static func matchIPPattern(_ pattern: String, ipString: String) -> Bool {
        if pattern.isEmpty || pattern == "*" {
            return true
        }

        // range, works for v4 and v6, e.g. 10.0.0.1-10.0.0.254 or fe80::1-fe80::ff
        if pattern.contains("-") {
            let parts = pattern.components(separatedBy: "-")
            guard parts.count == 2,
                  let lo = ipToBytes(parts[0].trimmingCharacters(in: .whitespaces)),
                  let hi = ipToBytes(parts[1].trimmingCharacters(in: .whitespaces)),
                  let target = ipToBytes(ipString),
                  lo.count == hi.count, target.count == lo.count else {
                return false
            }
            return compareBytes(target, lo) >= 0 && compareBytes(target, hi) <= 0
        }

        // v6 pattern (contains a colon)
        if pattern.contains(":") {
            return matchIPv6Pattern(pattern, ipString: ipString)
        }

        // v4 wildcard, e.g. 192.168.1.*
        let patternOctets = pattern.components(separatedBy: ".")
        let ipOctets = ipString.components(separatedBy: ".")
        if patternOctets.count != 4 || ipOctets.count != 4 {
            return false
        }
        for i in 0..<4 {
            if patternOctets[i] == "*" { continue }
            if patternOctets[i] != ipOctets[i] { return false }
        }
        return true
    }

    private static func matchIPv6Pattern(_ pattern: String, ipString: String) -> Bool {
        // prefix wildcard on leading hextets, e.g. 2001:db8:* (no :: compression)
        if pattern.hasSuffix("*") {
            guard let target = expandIPv6(ipString) else { return false }
            var groups = pattern.lowercased().dropLast()
                .split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            if groups.last == "" { groups.removeLast() }
            for (i, g) in groups.enumerated() {
                guard i < 8, !g.isEmpty, let value = UInt16(g, radix: 16) else { return false }
                if String(format: "%x", value) != target[i] { return false }
            }
            return true
        }

        // exact match, compared on normalized bytes so ::1 == 0:0:...:1
        guard let p = ipToBytes(pattern), let t = ipToBytes(ipString) else { return false }
        return p == t
    }
    
    private static func matchPortList(_ portList: String, port: UInt16) -> Bool {
        if portList.isEmpty || portList == "*" {
            return true
        }
        
        let patterns = portList.components(separatedBy: CharacterSet(charactersIn: ",;"))
        for pattern in patterns {
            let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            if matchPortPattern(trimmed, port: port) {
                return true
            }
        }
        return false
    }
    
    private static func matchPortPattern(_ pattern: String, port: UInt16) -> Bool {
        if pattern.isEmpty || pattern == "*" {
            return true
        }
        
        if let dashIndex = pattern.firstIndex(of: "-") {
            let startStr = String(pattern[..<dashIndex])
            let endStr = String(pattern[pattern.index(after: dashIndex)...])
            
            if let start = UInt16(startStr), let end = UInt16(endStr) {
                return port >= start && port <= end
            }
            return false
        }
        
        if let patternPort = UInt16(pattern) {
            return port == patternPort
        }
        return false
    }
}

class AppProxyProvider: NETransparentProxyProvider {
    
    // one log entry, kept as an enum so we don't allocate a dictionary per line,
    // the dict is only built when the gui drains a batch
    private enum LogEntry {
        case connection(proto: String, process: String, destination: String, port: String, proxy: String)
        case activity(timestamp: String, level: String, message: String)

        func toDict() -> [String: String] {
            switch self {
            case let .connection(proto, process, destination, port, proxy):
                return ["type": "connection", "protocol": proto, "process": process,
                        "destination": destination, "port": port, "proxy": proxy]
            case let .activity(timestamp, level, message):
                return ["type": "activity", "timestamp": timestamp, "level": level, "message": message]
            }
        }
    }

    // circular buffer for logs, avoids shifting the whole array on every pop
    private static let logCapacity = 500
    private var logBuffer = [LogEntry?](repeating: nil, count: AppProxyProvider.logCapacity)
    private var logHead = 0
    private var logTail = 0
    private var logCount = 0
    private let logQueueLock = NSLock()
    private let dateFormatter: ISO8601DateFormatter = ISO8601DateFormatter()
    
    // cache by pid + pid version so we don't call proc_pidpath on every
    // connection. the version changes when a pid is reused, so a new process
    // never inherits the previous owner's name
    private var pidCache: [UInt64: String] = [:]
    private let pidCacheLock = NSLock()
    private static let pidCacheMaxSize = 256
    
    private func getProcessName(from metaData: NEFlowMetaData) -> String? {
        guard let auditTokenData = metaData.sourceAppAuditToken else {
            return nil
        }
        guard auditTokenData.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }
        
        let (pid, pidVersion) = auditTokenData.withUnsafeBytes { ptr -> (pid_t, UInt32) in
            guard let baseAddress = ptr.baseAddress else { return (0, 0) }
            let token = baseAddress.assumingMemoryBound(to: UInt32.self)
            return (pid_t(token[5]), token[7])
        }
        
        guard pid > 0 else { return nil }
        let key = (UInt64(UInt32(pid)) << 32) | UInt64(pidVersion)
        
        pidCacheLock.lock()
        if let cached = pidCache[key] {
            pidCacheLock.unlock()
            return cached
        }
        pidCacheLock.unlock()

        var pathBuffer = [Int8](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN)) > 0 else {
            return nil
        }
        
        let fullPath = String(cString: pathBuffer)
        let processName = (fullPath as NSString).lastPathComponent
        
        // store in cache, evict everything if full - processes rarely hit this
        pidCacheLock.lock()
        if pidCache.count >= AppProxyProvider.pidCacheMaxSize {
            pidCache.removeAll(keepingCapacity: true)
        }
        pidCache[key] = processName
        pidCacheLock.unlock()
        
        return processName
    }
    
    // guarded by its own lock, the old OSAtomic compare-and-swap setter could
    // silently no-op if the stored value wasn't the exact expected one
    private var _trafficLoggingEnabled = true
    private let trafficLoggingLock = NSLock()
    private var trafficLoggingEnabled: Bool {
        get { trafficLoggingLock.lock(); defer { trafficLoggingLock.unlock() }; return _trafficLoggingEnabled }
        set { trafficLoggingLock.lock(); _trafficLoggingEnabled = newValue; trafficLoggingLock.unlock() }
    }
    
    private var rules: [ProxyRule] = []
    private let rulesLock = NSLock()
    private var nextRuleId: UInt32 = 1
    
    private struct StoredProxyConfig {
        let type: String
        let host: String
        let port: Int
        let username: String?
        let password: String?
    }
    private var storedProxyConfigs: [String: StoredProxyConfig] = [:]
    private let proxyLock = NSLock()
    
    private func log(_ message: String, level: String = "INFO") {
        appendLog(.activity(timestamp: dateFormatter.string(from: Date()), level: level, message: message))
    }

    private func appendLog(_ entry: LogEntry) {
        logQueueLock.lock()
        logBuffer[logTail] = entry
        logTail = (logTail + 1) % AppProxyProvider.logCapacity
        if logCount < AppProxyProvider.logCapacity {
            logCount += 1
        } else {
            // buffer full, bump head to drop the oldest entry
            logHead = (logHead + 1) % AppProxyProvider.logCapacity
        }
        logQueueLock.unlock()
    }

    override func startProxy(options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        
        let allTrafficRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .outbound
        )
        
        settings.includedNetworkRules = [allTrafficRule]

        startUDPSweepTimer()
        
        self.setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }
    
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        udpSweepTimer?.cancel()
        udpSweepTimer = nil
        udpLock.lock()
        let all = Array(udpAssociations.values)
        udpAssociations.removeAll()
        udpLock.unlock()
        for a in all {
            a.controlConnection.cancel()
            a.udpSession.cancel()
        }
        completionHandler()
    }
    
    // one association per udp flow, holds both channels so we tear the whole thing
    // down together when any side goes away
    private final class UDPAssociation {
        let clientFlow: NEAppProxyUDPFlow
        let controlConnection: NWTCPConnection  // socks5 tcp control channel, keeps the association alive
        let udpSession: NWUDPSession            // relay channel to the socks server
        let displayName: String
        var loggedDestinations = Set<String>()  // dedupe connection logs, bounded
        var isTornDown = false
        private var lastActivity = Date()
        private let activityLock = NSLock()

        func touch() {
            activityLock.lock(); lastActivity = Date(); activityLock.unlock()
        }

        func idleTime() -> TimeInterval {
            activityLock.lock(); defer { activityLock.unlock() }
            return Date().timeIntervalSince(lastActivity)
        }

        init(clientFlow: NEAppProxyUDPFlow, controlConnection: NWTCPConnection, udpSession: NWUDPSession, displayName: String) {
            self.clientFlow = clientFlow
            self.controlConnection = controlConnection
            self.udpSession = udpSession
            self.displayName = displayName
        }
    }
    private var udpAssociations: [NEAppProxyUDPFlow: UDPAssociation] = [:]
    private let udpLock = NSLock()

    // udp has no close signal we can rely on (quic flows come and go), so idle
    // associations are reaped here, otherwise each one pins a flow, a tcp
    // control connection and a udp session for the life of the extension
    private static let udpIdleTimeout: TimeInterval = 120
    private var udpSweepTimer: DispatchSourceTimer?

    private func startUDPSweepTimer() {
        udpSweepTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 30, repeating: 30, leeway: .seconds(5))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.udpLock.lock()
            let stale = self.udpAssociations.filter { $0.value.idleTime() > AppProxyProvider.udpIdleTimeout }.map { $0.key }
            self.udpLock.unlock()
            for flow in stale { self.teardownUDP(flow) }
        }
        timer.resume()
        udpSweepTimer = timer
    }

    // tcp and udp proxy handshakes have no timeout of their own, so a proxy that
    // accepts the connection and then goes quiet would pin the flow forever.
    // an id stays in this set until the handshake finishes or the timer fires.
    private var pendingHandshakes = Set<ObjectIdentifier>()
    private let handshakeLock = NSLock()
    private static let handshakeTimeout: TimeInterval = 20

    private func armHandshakeTimeout(flow: NEAppProxyFlow, connection: NWTCPConnection) {
        let id = ObjectIdentifier(connection)
        handshakeLock.lock(); pendingHandshakes.insert(id); handshakeLock.unlock()
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + AppProxyProvider.handshakeTimeout) { [weak self] in
            guard let self = self else { return }
            self.handshakeLock.lock()
            let timedOut = self.pendingHandshakes.remove(id) != nil
            self.handshakeLock.unlock()
            if timedOut {
                connection.cancel()
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
            }
        }
    }

    // false means the timeout already fired and tore everything down
    private func completeHandshake(_ connection: NWTCPConnection) -> Bool {
        handshakeLock.lock()
        defer { handshakeLock.unlock() }
        return pendingHandshakes.remove(ObjectIdentifier(connection)) != nil
    }

    private func closeRelay(_ flow: NEAppProxyTCPFlow, _ connection: NWTCPConnection, error: Error? = nil) {
        connection.cancel()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let message = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let action = message["action"] as? String else {
            completionHandler?(nil)
            return
        }
        
        switch action {
        case "getLogs":
            logQueueLock.lock()
            if logCount > 0 {
                let batchSize = min(100, logCount)
                var logsToSend: [[String: String]] = []
                logsToSend.reserveCapacity(batchSize)
                for _ in 0..<batchSize {
                    if let entry = logBuffer[logHead] {
                        logsToSend.append(entry.toDict())
                    }
                    logBuffer[logHead] = nil  // release the drained entry
                    logHead = (logHead + 1) % AppProxyProvider.logCapacity
                    logCount -= 1
                }
                logQueueLock.unlock()
                completionHandler?(try? JSONSerialization.data(withJSONObject: logsToSend))
            } else {
                logQueueLock.unlock()
                completionHandler?(nil)
            }
        case "setTrafficLogging":
            if let enabled = message["enabled"] as? Bool {
                trafficLoggingEnabled = enabled
                let response = ["status": "ok"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            } else {
                completionHandler?(nil)
            }
        case "setProxyConfigs":
            if let configs = message["configs"] as? [[String: Any]] {
                proxyLock.lock()
                storedProxyConfigs = [:]
                for configDict in configs {
                    guard let id = configDict["id"] as? String,
                          let type = configDict["proxyType"] as? String,
                          let host = configDict["proxyHost"] as? String,
                          let port = configDict["proxyPort"] as? Int else { continue }
                    storedProxyConfigs[id] = StoredProxyConfig(
                        type: type, host: host, port: port,
                        username: configDict["proxyUsername"] as? String,
                        password: configDict["proxyPassword"] as? String
                    )
                }
                proxyLock.unlock()
                log("Proxy configs updated: \(storedProxyConfigs.count) config(s)")
            }
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["status": "ok"]))

        case "addRule":
            if let ruleData = try? JSONSerialization.data(withJSONObject: message),
               var rule = try? JSONDecoder().decode(ProxyRule.self, from: ruleData) {
                rulesLock.lock()
                rule.ruleId = nextRuleId
                nextRuleId += 1
                rules.append(rule)
                rulesLock.unlock()

                let response: [String: Any] = [
                    "status": "ok",
                    "ruleId": rule.ruleId,
                    "processNames": rule.processNames,
                    "targetHosts": rule.targetHosts,
                    "targetPorts": rule.targetPorts,
                    "protocol": rule.ruleProtocol.rawValue,
                    "action": rule.action,
                    "enabled": rule.enabled
                ]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            } else {
                let response = ["status": "error", "message": "Invalid rule format"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            }
        
        case "clearRules":
            rulesLock.lock()
            let count = rules.count
            rules.removeAll()
            rulesLock.unlock()
            let response: [String: Any] = ["status": "ok", "cleared": count]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        
        case "clearConfig":
            // drop the stored proxy configs so credentials don't sit in memory after stop
            proxyLock.lock()
            storedProxyConfigs.removeAll()
            proxyLock.unlock()
            completionHandler?(try? JSONSerialization.data(withJSONObject: ["status": "ok"]))
        default:
            completionHandler?(nil)
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }
    
    override func wake() {
    }
    
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return handleTCPFlow(tcpFlow)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            return handleUDPFlow(udpFlow)
        }
        return false
    }
    
    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
        let metaData = flow.metaData
        let processPath = metaData.sourceAppSigningIdentifier
        
        // never proxy our own traffic, it would loop
        if processPath == "com.interceptsuite.ProxyBridge" || processPath == "com.interceptsuite.ProxyBridge.extension" {
            return false
        }

        let remoteEndpoint = flow.remoteEndpoint
        var destination = ""
        var portNum: UInt16 = 0
        var portStr = ""
        
        if let remoteHost = remoteEndpoint as? NWHostEndpoint {
            destination = remoteHost.hostname
            portStr = remoteHost.port
            portNum = UInt16(portStr) ?? 0
        } else {
            destination = String(describing: remoteEndpoint)
            portStr = "unknown"
        }
        
        let processName = getProcessName(from: metaData)
        let displayName = processName ?? processPath
        
        // domains that resolved to this ip (from the dns proxy), used for domain
        // rules and to show the hostname in the log instead of the raw ip
        let domains = DNSMapStore.shared.domains(forIP: destination)
        let logDest = domains.first ?? destination

        proxyLock.lock()
        let hasProxyConfig = !storedProxyConfigs.isEmpty
        proxyLock.unlock()

        if !hasProxyConfig {
            sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct")
            return false
        }

        let matchedRule = findMatchingRule(bundleId: processPath, processName: processName, destination: destination, port: portNum, connectionProtocol: .tcp, checkIpPort: true, domains: domains)

        if let rule = matchedRule {
            switch rule.action {
            case "DIRECT":
                sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct")
                return false
            case "BLOCK":
                sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "BLOCK")
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return true
            default:
                proxyLock.lock()
                let config = storedProxyConfigs[rule.action]
                proxyLock.unlock()
                guard let config = config else {
                    // rule points at a proxy that no longer exists, let it go direct
                    sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct")
                    return false
                }
                sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: proxyLabel(config))
                proxyTCPFlow(flow, destination: destination, port: portNum, config: config)
                return true
            }
        } else {
            sendLogToApp(protocol: "TCP", process: displayName, destination: logDest, port: portStr, proxy: "Direct")
            return false
        }
    }

    // human readable label for the connection log, e.g. SOCKS5 127.0.0.1:1080
    private func proxyLabel(_ config: StoredProxyConfig) -> String {
        return "\(config.type.uppercased()) \(config.host):\(config.port)"
    }
    
    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
        let metaData = flow.metaData
        let processPath = metaData.sourceAppSigningIdentifier
        let processName = getProcessName(from: metaData)
        let displayName = processName ?? processPath
        
        if processPath == "com.interceptsuite.ProxyBridge" || processPath == "com.interceptsuite.ProxyBridge.extension" {
            return false
        }
        
        proxyLock.lock()
        let hasAnySocks5 = storedProxyConfigs.values.contains { $0.type.lowercased() == "socks5" }
        proxyLock.unlock()

        if !hasAnySocks5 {
            return false
        }

        let matchedRule = findMatchingRule(bundleId: processPath, processName: processName, destination: "", port: 0, connectionProtocol: .udp, checkIpPort: false)

        if let rule = matchedRule {
            let action = rule.action
            switch action {
            case "DIRECT":
                sendLogToApp(protocol: "UDP", process: displayName, destination: "unknown", port: "unknown", proxy: "Direct")
                return false
            case "BLOCK":
                sendLogToApp(protocol: "UDP", process: displayName, destination: "unknown", port: "unknown", proxy: "BLOCK")
                // a handled flow that is never closed stays pinned in the extension
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return true
            default:
                proxyLock.lock()
                let matched = storedProxyConfigs[action]
                proxyLock.unlock()
                guard let socks5Config = matched, socks5Config.type.lowercased() == "socks5" else { return false }
                flow.open(withLocalEndpoint: nil) { [weak self] error in
                    guard let self = self else { return }
                    // a closed flow here is normal churn (quic opening and dropping
                    // udp/443 flows constantly), nothing to do and not worth logging
                    if error != nil {
                        return
                    }
                    // pass the resolved display name (curl), not the raw signing id (curl-<hash>)
                    self.proxyUDPFlowViaSOCKS5(flow, displayName: displayName, socksHost: socks5Config.host, socksPort: socks5Config.port, username: socks5Config.username, password: socks5Config.password)
                }
                return true
            }
        } else {
            sendLogToApp(protocol: "UDP", process: displayName, destination: "unknown", port: "unknown", proxy: "Direct")
            return false
        }
    }
    
    // handshake failed before an association existed, so drop the control
    // connection and close the flow instead of leaking them
    private func failUDPHandshake(_ clientFlow: NEAppProxyUDPFlow, _ tcpConnection: NWTCPConnection, _ reason: String) {
        log(reason, level: "ERROR")
        tcpConnection.cancel()
        clientFlow.closeReadWithError(nil)
        clientFlow.closeWriteWithError(nil)
    }

    private func proxyUDPFlowViaSOCKS5(_ clientFlow: NEAppProxyUDPFlow, displayName: String, socksHost: String, socksPort: Int, username: String?, password: String?) {
        let proxyEndpoint = NWHostEndpoint(hostname: socksHost, port: String(socksPort))
        let tcpConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        armHandshakeTimeout(flow: clientFlow, connection: tcpConnection)

        // offer username/password auth when we have credentials, same as the tcp path
        let useAuth = (username != nil && password != nil)
        let greeting: [UInt8] = useAuth ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00]

        tcpConnection.write(Data(greeting)) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP greeting failed: \(error.localizedDescription)")
                return
            }

            tcpConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP greeting response failed: \(error.localizedDescription)")
                    return
                }

                guard let data = data, data.count == 2, data[0] == 0x05 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP greeting response invalid")
                    return
                }

                switch data[1] {
                case 0x00:
                    self.sendSOCKS5UDPAssociate(clientFlow: clientFlow, tcpConnection: tcpConnection, socksHost: socksHost, displayName: displayName)
                case 0x02:
                    self.sendSOCKS5UDPAuth(clientFlow: clientFlow, tcpConnection: tcpConnection, socksHost: socksHost, displayName: displayName, username: username ?? "", password: password ?? "")
                default:
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP no acceptable auth method")
                }
            }
        }
    }

    private func sendSOCKS5UDPAuth(clientFlow: NEAppProxyUDPFlow, tcpConnection: NWTCPConnection, socksHost: String, displayName: String, username: String, password: String) {
        let user = Array(username.utf8), pass = Array(password.utf8)
        guard user.count <= 255, pass.count <= 255 else {
            self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP credentials too long")
            return
        }

        var authData = Data()
        authData.append(0x01)
        authData.append(UInt8(user.count))
        authData.append(contentsOf: user)
        authData.append(UInt8(pass.count))
        authData.append(contentsOf: pass)

        tcpConnection.write(authData) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP auth write failed: \(error.localizedDescription)")
                return
            }

            tcpConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP auth response failed: \(error.localizedDescription)")
                    return
                }

                guard let data = data, data.count == 2, data[1] == 0x00 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP auth rejected")
                    return
                }

                self.sendSOCKS5UDPAssociate(clientFlow: clientFlow, tcpConnection: tcpConnection, socksHost: socksHost, displayName: displayName)
            }
        }
    }

    private func sendSOCKS5UDPAssociate(clientFlow: NEAppProxyUDPFlow, tcpConnection: NWTCPConnection, socksHost: String, displayName: String) {
        var request = Data()
        request.append(0x05)
        request.append(0x03)
        request.append(0x00)
        request.append(0x01)
        request.append(contentsOf: [0, 0, 0, 0])
        request.append(contentsOf: [0, 0])
        
        tcpConnection.write(request) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP ASSOCIATE failed: \(error.localizedDescription)")
                return
            }

            // read at least VER+REP so we can report the reason even on a short reply
            tcpConnection.readMinimumLength(2, maximumLength: 512) { [weak self] data, error in
                guard let self = self else { return }

                if let error = error {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP ASSOCIATE response error: \(error.localizedDescription)")
                    return
                }

                guard let data = data, data.count >= 2, data[0] == 0x05 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP ASSOCIATE bad reply (\(data?.count ?? 0) bytes)")
                    return
                }

                let rep = data[1]
                guard rep == 0x00 else {
                    let reason = self.socksReplyReason(rep)
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP ASSOCIATE rejected, REP=0x\(String(format: "%02x", rep)) (\(reason))")
                    return
                }

                guard data.count >= 10 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP ASSOCIATE reply too short (\(data.count) bytes)")
                    return
                }

                let (parsedHost, relayPort) = self.parseSOCKS5Address(from: data, offset: 3)
                // many socks servers reply 0.0.0.0 meaning "reuse the control connection host"
                let relayHost = (parsedHost == "0.0.0.0" || parsedHost == "::" || parsedHost.isEmpty) ? socksHost : parsedHost
                guard relayPort != 0 else {
                    self.failUDPHandshake(clientFlow, tcpConnection, "SOCKS5 UDP ASSOCIATE returned no relay port")
                    return
                }
                self.relayUDPThroughSOCKS5(clientFlow: clientFlow, relayHost: relayHost, relayPort: relayPort, tcpConnection: tcpConnection, displayName: displayName)
            }
        }
    }
    
    // human readable name for a socks5 REP code, from RFC 1928
    private func socksReplyReason(_ rep: UInt8) -> String {
        switch rep {
        case 0x01: return "general failure"
        case 0x02: return "not allowed by ruleset"
        case 0x03: return "network unreachable"
        case 0x04: return "host unreachable"
        case 0x05: return "connection refused"
        case 0x06: return "TTL expired"
        case 0x07: return "command not supported"
        case 0x08: return "address type not supported"
        default: return "unknown"
        }
    }

    private func parseSOCKS5Address(from data: Data, offset: Int) -> (String, UInt16) {
        guard data.count > offset else { return ("0.0.0.0", 0) }
        let atyp = data[offset]

        if atyp == 0x01 {
            guard data.count >= offset + 7 else { return ("0.0.0.0", 0) }
            let ip = "\(data[offset+1]).\(data[offset+2]).\(data[offset+3]).\(data[offset+4])"
            let port = (UInt16(data[offset+5]) << 8) | UInt16(data[offset+6])
            return (ip, port)
        } else if atyp == 0x04 {
            guard data.count >= offset + 19 else { return ("0.0.0.0", 0) }
            var ipv6Parts: [String] = []
            for i in 0..<8 {
                let idx = offset + 1 + (i * 2)
                let part = (UInt16(data[idx]) << 8) | UInt16(data[idx+1])
                ipv6Parts.append(String(format: "%x", part))
            }
            let ip = ipv6Parts.joined(separator: ":")
            let port = (UInt16(data[offset+17]) << 8) | UInt16(data[offset+18])
            return (ip, port)
        } else if atyp == 0x03 {
            guard data.count >= offset + 2 else { return ("0.0.0.0", 0) }
            let len = Int(data[offset+1])
            guard data.count >= offset + 2 + len + 2 else { return ("0.0.0.0", 0) }
            let domain = String(data: data[(offset+2)..<(offset+2+len)], encoding: .utf8) ?? "unknown"
            let port = (UInt16(data[offset+2+len]) << 8) | UInt16(data[offset+2+len+1])
            return (domain, port)
        }

        return ("0.0.0.0", 0)
    }
    
    private func relayUDPThroughSOCKS5(clientFlow: NEAppProxyUDPFlow, relayHost: String, relayPort: UInt16, tcpConnection: NWTCPConnection, displayName: String) {
        guard completeHandshake(tcpConnection) else { return }
        let relayEndpoint = NWHostEndpoint(hostname: relayHost, port: String(relayPort))
        let udpSession = self.createUDPSession(to: relayEndpoint, from: nil)

        let association = UDPAssociation(clientFlow: clientFlow, controlConnection: tcpConnection, udpSession: udpSession, displayName: displayName)

        udpLock.lock()
        let existing = udpAssociations[clientFlow]
        udpAssociations[clientFlow] = association
        udpLock.unlock()
        // if the app reused a flow, drop the stale association first
        existing?.controlConnection.cancel()
        existing?.udpSession.cancel()

        readAndForwardClientUDP(association)
        readAndForwardRelayUDP(association)
        // note: we deliberately don't read the control connection to detect close.
        // holding a strong ref keeps the associate alive, and reading it risks a
        // spurious teardown that would EPIPE the app's udp socket.
    }

    // idempotent, cancels both channels and closes the flow exactly once
    private func teardownUDP(_ flow: NEAppProxyUDPFlow) {
        udpLock.lock()
        guard let assoc = udpAssociations.removeValue(forKey: flow), !assoc.isTornDown else {
            udpLock.unlock()
            return
        }
        assoc.isTornDown = true
        udpLock.unlock()

        assoc.controlConnection.cancel()
        assoc.udpSession.cancel()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
    }

    private func readAndForwardClientUDP(_ association: UDPAssociation) {
        let clientFlow = association.clientFlow
        clientFlow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            if let error = error {
                self.log("UDP read error: \(error.localizedDescription)", level: "ERROR")
                self.teardownUDP(clientFlow)
                return
            }

            // nil or empty datagrams with no error = flow closed for reading.
            // re-arming on empty spins at 100% cpu because the read completes
            // immediately forever once the flow is closed (issue #89 / pr #90)
            guard let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else {
                self.teardownUDP(clientFlow)
                return
            }

            association.touch()
            var toSend: [Data] = []
            toSend.reserveCapacity(datagrams.count)

            for i in 0..<min(datagrams.count, endpoints.count) {
                guard let nwHost = endpoints[i] as? NWHostEndpoint else { continue }
                let destHost = nwHost.hostname
                let destPort = UInt16(nwHost.port) ?? 0
                guard destPort != 0 else { continue }

                // log each distinct destination once, cap the set so it can't grow forever
                if !association.loggedDestinations.contains(destHost) {
                    if association.loggedDestinations.count < 64 {
                        association.loggedDestinations.insert(destHost)
                    }
                    self.sendLogToApp(protocol: "UDP", process: association.displayName, destination: destHost, port: nwHost.port, proxy: "SOCKS5")
                }

                if let encapsulated = self.encapsulateSOCKS5UDP(datagram: datagrams[i], destHost: destHost, destPort: destPort) {
                    toSend.append(encapsulated)
                }
            }

            if !toSend.isEmpty {
                association.udpSession.writeMultipleDatagrams(toSend) { [weak self] error in
                    if let error = error {
                        self?.log("UDP write error: \(error.localizedDescription)", level: "ERROR")
                    }
                }
            }

            self.readAndForwardClientUDP(association)
        }
    }

    private func readAndForwardRelayUDP(_ association: UDPAssociation) {
        let clientFlow = association.clientFlow
        association.udpSession.setReadHandler({ [weak self] datagrams, error in
            guard let self = self else { return }

            if let error = error {
                // stop reading the relay but don't close the app's flow, let it
                // time out on its own instead of getting a hard EPIPE
                self.log("UDP relay error: \(error.localizedDescription)", level: "ERROR")
                return
            }

            guard let datagrams = datagrams, !datagrams.isEmpty else { return }
            association.touch()

            var payloads: [Data] = []
            var endpoints: [NWEndpoint] = []
            payloads.reserveCapacity(datagrams.count)
            endpoints.reserveCapacity(datagrams.count)

            for datagram in datagrams {
                if let (payload, destHost, destPort) = self.decapsulateSOCKS5UDPWithEndpoint(datagram: datagram) {
                    payloads.append(payload)
                    endpoints.append(NWHostEndpoint(hostname: destHost, port: String(destPort)))
                }
            }

            if !payloads.isEmpty {
                clientFlow.writeDatagrams(payloads, sentBy: endpoints) { [weak self] error in
                    if let error = error {
                        self?.log("UDP response write error: \(error.localizedDescription)", level: "ERROR")
                    }
                }
            }
        }, maxDatagrams: 32)
    }
    
    private func encapsulateSOCKS5UDP(datagram: Data, destHost: String, destPort: UInt16) -> Data? {
        // a udp payload can be up to ~65507 bytes, don't drop mtu-sized quic
        // packets, let the network fragment if it must
        if datagram.count > 65507 {
            return nil
        }

        var header = Data()
        header.append(contentsOf: [0, 0])
        header.append(0x00)
        
        if let ipv4 = IPv4Address(destHost) {
            header.append(0x01)
            header.append(contentsOf: ipv4.rawValue)
        } else if let ipv6 = IPv6Address(destHost) {
            header.append(0x04)
            header.append(contentsOf: ipv6.rawValue)
        } else {
            // length prefix must be the utf8 byte count, not the character count
            let hostBytes = Array(destHost.utf8)
            guard hostBytes.count <= 255 else {
                self.log("Domain name too long: \(hostBytes.count) bytes", level: "ERROR")
                return nil
            }
            header.append(0x03)
            header.append(UInt8(hostBytes.count))
            header.append(contentsOf: hostBytes)
        }
        
        header.append(UInt8(destPort >> 8))
        header.append(UInt8(destPort & 0xFF))
        
        var result = header
        result.append(datagram)
        return result
    }
    
    private func decapsulateSOCKS5UDPWithEndpoint(datagram: Data) -> (Data, String, UInt16)? {
        guard datagram.count > 10 else { return nil }

        // byte 2 is FRAG, we don't reassemble so drop any fragmented datagram
        guard datagram[2] == 0x00 else { return nil }

        let atyp = datagram[3]
        var headerLen = 4
        var destHost = ""
        var destPort: UInt16 = 0

        if atyp == 0x01 {
            // ipv4 is 4 bytes + 2 port, already covered by count > 10
            destHost = "\(datagram[4]).\(datagram[5]).\(datagram[6]).\(datagram[7])"
            destPort = (UInt16(datagram[8]) << 8) | UInt16(datagram[9])
            headerLen += 6
        } else if atyp == 0x04 {
            // ipv6 needs 16 bytes + 2 port
            guard datagram.count >= 22 else { return nil }
            var ipv6Parts: [String] = []
            for i in 0..<8 {
                let idx = 4 + (i * 2)
                let part = (UInt16(datagram[idx]) << 8) | UInt16(datagram[idx+1])
                ipv6Parts.append(String(format: "%x", part))
            }
            destHost = ipv6Parts.joined(separator: ":")
            destPort = (UInt16(datagram[20]) << 8) | UInt16(datagram[21])
            headerLen += 18
        } else if atyp == 0x03 {
            // byte 4 is the domain length, then the domain, then 2 port bytes
            guard datagram.count >= 6 else { return nil }
            let domainLen = Int(datagram[4])
            guard datagram.count >= 5 + domainLen + 2 else { return nil }
            destHost = String(data: datagram[5..<(5+domainLen)], encoding: .utf8) ?? "unknown"
            destPort = (UInt16(datagram[5+domainLen]) << 8) | UInt16(datagram[5+domainLen+1])
            headerLen += 1 + domainLen + 2
        } else {
            return nil
        }

        guard datagram.count > headerLen else { return nil }

        let payload = datagram[headerLen...]
        return (Data(payload), destHost, destPort)
    }
    
    private func proxyTCPFlow(_ flow: NEAppProxyTCPFlow, destination: String, port: UInt16, config: StoredProxyConfig) {
        let proxyEndpoint = NWHostEndpoint(hostname: config.host, port: String(config.port))
        let proxyConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        armHandshakeTimeout(flow: flow, connection: proxyConnection)

        switch config.type.lowercased() {
        case "socks5":
            handleSOCKS5Proxy(clientFlow: flow, proxyConnection: proxyConnection, destination: destination, port: port, username: config.username, password: config.password)
        case "http":
            handleHTTPProxy(clientFlow: flow, proxyConnection: proxyConnection, destination: destination, port: port, username: config.username, password: config.password)
        default:
            log("unsupported proxy type: \(config.type)", level: "ERROR")
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
    }
    
    private func handleSOCKS5Proxy(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, destination: String, port: UInt16, username: String?, password: String?) {
        var greeting: [UInt8]
        if username != nil && password != nil {
            greeting = [0x05, 0x02, 0x00, 0x02]
        } else {
            greeting = [0x05, 0x01, 0x00]
        }
        
        let greetingData = Data(greeting)
        proxyConnection.write(greetingData) { [weak self] error in
            if let error = error {
                self?.log("SOCKS5 greeting write failed: \(error.localizedDescription)", level: "ERROR")
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("SOCKS5 greeting response failed: \(error.localizedDescription)", level: "ERROR")
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data, data.count == 2 else {
                    self.log("SOCKS5 invalid greeting response", level: "ERROR")
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                let version = data[0]
                let method = data[1]
                
                if version != 0x05 {
                    self.log("SOCKS5 invalid version: \(version)", level: "ERROR")
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                if method == 0x00 {
                    self.sendSOCKS5ConnectRequest(clientFlow: clientFlow, proxyConnection: proxyConnection, destination: destination, port: port)
                } else if method == 0x02 {
                    self.sendSOCKS5Auth(clientFlow: clientFlow, proxyConnection: proxyConnection, destination: destination, port: port, username: username ?? "", password: password ?? "")
                } else {
                    self.log("SOCKS5 no acceptable auth method: \(method)", level: "ERROR")
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                }
            }
        }
    }
    
    private func sendSOCKS5Auth(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, destination: String, port: UInt16, username: String, password: String) {
        let user = Array(username.utf8), pass = Array(password.utf8)
        guard user.count <= 255, pass.count <= 255 else {
            log("SOCKS5 credentials too long", level: "ERROR")
            closeRelay(clientFlow, proxyConnection)
            return
        }
        var authData = Data()
        authData.append(0x01)
        authData.append(UInt8(user.count))
        authData.append(contentsOf: user)
        authData.append(UInt8(pass.count))
        authData.append(contentsOf: pass)
        
        proxyConnection.write(authData) { [weak self] error in
            if let error = error {
                self?.log("SOCKS5 auth write failed: \(error.localizedDescription)", level: "ERROR")
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("SOCKS5 auth response failed: \(error.localizedDescription)", level: "ERROR")
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data, data.count == 2, data[1] == 0x00 else {
                    self.log("SOCKS5 auth failed", level: "ERROR")
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                self.sendSOCKS5ConnectRequest(clientFlow: clientFlow, proxyConnection: proxyConnection, destination: destination, port: port)
            }
        }
    }
    
    private func sendSOCKS5ConnectRequest(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, destination: String, port: UInt16) {
        var request = Data()
        request.append(0x05)
        request.append(0x01)
        request.append(0x00)
        
        if let ipAddr = IPv4Address(destination) {
            request.append(0x01)
            request.append(contentsOf: ipAddr.rawValue)
        } else if let ipAddr = IPv6Address(destination) {
            request.append(0x04)
            request.append(contentsOf: ipAddr.rawValue)
        } else {
            let hostBytes = Array(destination.utf8)
            guard hostBytes.count <= 255 else {
                log("SOCKS5 destination name too long", level: "ERROR")
                closeRelay(clientFlow, proxyConnection)
                return
            }
            request.append(0x03)
            request.append(UInt8(hostBytes.count))
            request.append(contentsOf: hostBytes)
        }
        
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xFF))
        
        proxyConnection.write(request) { [weak self] error in
            if let error = error {
                self?.log("SOCKS5 connect write failed: \(error.localizedDescription)", level: "ERROR")
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(10, maximumLength: 512) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("SOCKS5 connect response failed: \(error.localizedDescription)", level: "ERROR")
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data, data.count >= 10, data[0] == 0x05, data[1] == 0x00 else {
                    self.log("SOCKS5 connect failed", level: "ERROR")
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                self.relayData(clientFlow: clientFlow, proxyConnection: proxyConnection)
            }
        }
    }
    
    private func handleHTTPProxy(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, destination: String, port: UInt16, username: String?, password: String?) {
        // ipv6 literals must be bracketed in the request line and Host header
        let host = IPv6Address(destination) != nil ? "[\(destination)]" : destination
        var request = "CONNECT \(host):\(port) HTTP/1.1\r\n"
        request += "Host: \(host):\(port)\r\n"
        
        if let username = username, let password = password {
            let credentials = "\(username):\(password)"
            if let credData = credentials.data(using: .utf8) {
                let base64Creds = credData.base64EncodedString()
                request += "Proxy-Authorization: Basic \(base64Creds)\r\n"
            }
        }
        
        request += "\r\n"
        
        guard let requestData = request.data(using: .utf8) else {
            log("HTTP CONNECT request encoding failed", level: "ERROR")
            clientFlow.closeReadWithError(nil)
            clientFlow.closeWriteWithError(nil)
            proxyConnection.cancel()
            return
        }
        
        proxyConnection.write(requestData) { [weak self] error in
            if let error = error {
                self?.log("HTTP CONNECT write failed: \(error.localizedDescription)", level: "ERROR")
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.readMinimumLength(1, maximumLength: 8192) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("HTTP CONNECT response failed: \(error.localizedDescription)", level: "ERROR")
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                    proxyConnection.cancel()
                    return
                }
                
                guard let data = data,
                      let response = String(data: data, encoding: .utf8) else {
                    self.log("HTTP CONNECT invalid response", level: "ERROR")
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                    return
                }
                
                if response.contains("200") {
                    self.relayData(clientFlow: clientFlow, proxyConnection: proxyConnection)
                } else {
                    self.log("HTTP CONNECT failed: \(response)", level: "ERROR")
                    clientFlow.closeReadWithError(nil)
                    clientFlow.closeWriteWithError(nil)
                    proxyConnection.cancel()
                }
            }
        }
    }
    
    private func relayData(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection) {
        guard completeHandshake(proxyConnection) else { return }
        clientFlow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.log("Failed to open client flow: \(error.localizedDescription)", level: "ERROR")
                self?.closeRelay(clientFlow, proxyConnection, error: error)
                return
            }
            
            self?.relayClientToProxy(clientFlow: clientFlow, proxyConnection: proxyConnection)
            self?.relayProxyToClient(clientFlow: clientFlow, proxyConnection: proxyConnection)
        }
    }
    
    private func relayClientToProxy(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection) {
        clientFlow.readData { [weak self] data, error in
            if let error = error {
                // ignore expected errors
                let code = (error as NSError).code
                if code != 57 && code != 54 && code != 89 {
                    self?.log("Client read error: \(error.localizedDescription)", level: "ERROR")
                }
                self?.closeRelay(clientFlow, proxyConnection)
                return
            }
            
            guard let data = data, !data.isEmpty else {
                self?.closeRelay(clientFlow, proxyConnection)
                return
            }
            
            proxyConnection.write(data) { error in
                if let error = error {
                    self?.log("Proxy write error: \(error.localizedDescription)", level: "ERROR")
                    self?.closeRelay(clientFlow, proxyConnection, error: error)
                } else {
                    self?.relayClientToProxy(clientFlow: clientFlow, proxyConnection: proxyConnection)
                }
            }
        }
    }
    
    private func relayProxyToClient(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection) {
        proxyConnection.readMinimumLength(1, maximumLength: 65536) { [weak self] data, error in
            if let error = error {
                let code = (error as NSError).code
                if code != 57 && code != 54 && code != 89 {
                    self?.log("Proxy read error: \(error.localizedDescription)", level: "ERROR")
                }
                self?.closeRelay(clientFlow, proxyConnection)
                return
            }
            
            guard let data = data, !data.isEmpty else {
                self?.closeRelay(clientFlow, proxyConnection)
                return
            }
            
            clientFlow.write(data) { error in
                if let error = error {
                    self?.log("Client write error: \(error.localizedDescription)", level: "ERROR")
                    self?.closeRelay(clientFlow, proxyConnection, error: error)
                } else {
                    self?.relayProxyToClient(clientFlow: clientFlow, proxyConnection: proxyConnection)
                }
            }
        }
    }
    
    private func findMatchingRule(bundleId: String, processName: String?, destination: String, port: UInt16, connectionProtocol: RuleProtocol, checkIpPort: Bool, domains: [String] = []) -> ProxyRule? {
        rulesLock.lock()
        let currentRules = rules
        rulesLock.unlock()

        var wildcardRule: ProxyRule? = nil

        for rule in currentRules {
            guard rule.enabled else { continue }

            if rule.ruleProtocol != .both && rule.ruleProtocol != connectionProtocol {
                continue
            }

            let isWildcardProcess = (rule.processNames == "*" || rule.processNames.isEmpty)

            if isWildcardProcess {
                let hasIpFilter = (rule.targetHosts != "*" && !rule.targetHosts.isEmpty)
                let hasPortFilter = (rule.targetPorts != "*" && !rule.targetPorts.isEmpty)

                if hasIpFilter || hasPortFilter {
                    // udp has no destination here, so a filtered wildcard can't match
                    if checkIpPort, rule.matchesHost(ip: destination, domains: domains), rule.matchesPort(port) {
                        return rule
                    }
                    continue
                }

                // pure wildcard, keep the first one as a fallback
                if wildcardRule == nil {
                    wildcardRule = rule
                }
                continue
            }

            if rule.matchesProcess(bundleId: bundleId, processName: processName) {
                if checkIpPort {
                    if rule.matchesHost(ip: destination, domains: domains) && rule.matchesPort(port) {
                        return rule
                    }
                } else {
                    // udp matches on process alone
                    return rule
                }
            }
        }

        if let wildcardRule = wildcardRule {
            return wildcardRule
        }
        
        return nil
    }
    
    private func sendLogToApp(protocol: String, process: String, destination: String, port: String, proxy: String) {
        guard trafficLoggingEnabled else { return }
        appendLog(.connection(proto: `protocol`, process: process, destination: destination, port: port, proxy: proxy))
    }
}



import NetworkExtension
import Darwin  // For audit_token_t, audit_token_to_pid, proc_pidpath, PROC_PIDPATHINFO_MAXSIZE

enum RuleProtocol: String, Codable {
    case tcp = "TCP"
    case udp = "UDP"
    case both = "BOTH"
}

enum RuleAction: String, Codable {
    case proxy = "PROXY"
    case direct = "DIRECT"
    case block = "BLOCK"
}

struct ProxyRule: Codable {
    var ruleId: UInt32
    let processNames: String
    let targetHosts: String
    let targetPorts: String
    let ruleProtocol: RuleProtocol
    let action: RuleAction
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
        self.action = try container.decode(RuleAction.self, forKey: .action)
        self.enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }
    
    init(ruleId: UInt32, processNames: String, targetHosts: String, targetPorts: String, ruleProtocol: RuleProtocol, action: RuleAction, enabled: Bool) {
        self.ruleId = ruleId
        self.processNames = processNames
        self.targetHosts = targetHosts
        self.targetPorts = targetPorts
        self.ruleProtocol = ruleProtocol
        self.action = action
        self.enabled = enabled
    }
    
    func matchesProcess(_ processPath: String) -> Bool {
        return Self.matchProcessList(processNames, processPath: processPath)
    }
    
    func matchesIP(_ ipString: String) -> Bool {
        return Self.matchIPList(targetHosts, ipString: ipString)
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
        
        if pattern.hasSuffix("*") {
            let prefix = String(pattern.dropLast())
            return matchTarget.lowercased().hasPrefix(prefix.lowercased())
        }
        
        if pattern.hasPrefix("*") {
            let suffix = String(pattern.dropFirst())
            return matchTarget.lowercased().hasSuffix(suffix.lowercased())
        }
        
        if let starIndex = pattern.firstIndex(of: "*") {
            let prefix = String(pattern[..<starIndex])
            let suffix = String(pattern[pattern.index(after: starIndex)...])
            let lower = matchTarget.lowercased()
            return lower.hasPrefix(prefix.lowercased()) && lower.hasSuffix(suffix.lowercased())
        }
        
        return matchTarget.lowercased() == pattern.lowercased()
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
    
    private static func matchIPPattern(_ pattern: String, ipString: String) -> Bool {
        if pattern.isEmpty || pattern == "*" {
            return true
        }
        
        let patternOctets = pattern.components(separatedBy: ".")
        let ipOctets = ipString.components(separatedBy: ".")
        
        if patternOctets.count != 4 || ipOctets.count != 4 {
            return false
        }
        
        for i in 0..<4 {
            if patternOctets[i] == "*" {
                continue
            }
            if patternOctets[i] != ipOctets[i] {
                return false
            }
        }
        return true
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
    
    private var logQueue: [[String: String]] = []
    private let logQueueLock = NSLock()
    
    private var trafficLoggingEnabled = true
    
    private var rules: [ProxyRule] = []
    private let rulesLock = NSLock()
    private var nextRuleId: UInt32 = 1
    
    private var proxyType: String?
    private var proxyHost: String?
    private var proxyPort: Int?
    private var proxyUsername: String?
    private var proxyPassword: String?
    private let proxyLock = NSLock()
    
    private func log(_ message: String, level: String = "INFO") {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let logEntry: [String: String] = [
            "timestamp": timestamp,
            "level": level,
            "message": message
        ]
        
        logQueueLock.lock()
        logQueue.append(logEntry)
        if logQueue.count > 1000 {
            logQueue.removeFirst()
        }
        logQueueLock.unlock()
    }
    
    /// Extracts the executable path of a process from its audit token.
    ///
    /// This function uses the audit token to get the process ID (PID), then retrieves
    /// the full path to the process executable using proc_pidpath().
    ///
    /// - Parameter auditToken: The audit token data from NEFlowMetaData.sourceAppAuditToken
    /// - Returns: The full path to the process executable, or nil if:
    ///   - The audit token size is invalid
    ///   - The process no longer exists
    ///   - The calling process lacks permission to access the process information
    ///   - proc_pidpath() fails for any other reason
    ///
    /// - Note: This is a workaround for Apple's Network Extension API limitation that doesn't
    ///         provide direct access to process names or paths. It may fail in some edge cases
    ///         due to security restrictions or race conditions.
    private func getExecutablePath(from auditToken: Data) -> String? {
        guard auditToken.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }
        
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { tokenPtr in
            auditToken.copyBytes(to: tokenPtr)
        }
        
        let pid = audit_token_to_pid(token)
        
        let pathBufferSize = Int(PROC_PIDPATHINFO_MAXSIZE)
        var pathBuffer = [CChar](repeating: 0, count: pathBufferSize)
        
        let result = pathBuffer.withUnsafeMutableBufferPointer { bufferPtr in
            proc_pidpath(pid, bufferPtr.baseAddress, UInt32(pathBufferSize))
        }
        
        guard result > 0 else {
            return nil
        }
        
        return String(cString: pathBuffer)
    }
    
    /// Extracts process identifiers from network flow metadata.
    ///
    /// This function retrieves both the bundle identifier (always available) and the
    /// executable path (when available) for the process that originated the network flow.
    ///
    /// - Parameter metaData: The NEFlowMetaData from the network flow
    /// - Returns: A tuple containing:
    ///   - bundleId: The application bundle identifier (e.g., "com.example.app") or "unknown"
    ///   - executablePath: The full path to the executable (e.g., "/usr/local/bin/ciadpi"),
    ///                     or nil if the path cannot be determined
    ///
    /// - Note: The executable path is extracted from the sourceAppAuditToken when available.
    ///         For processes without app bundles (standalone binaries), this provides the
    ///         only reliable way to identify the process.
    private func getProcessIdentifiers(from metaData: NEFlowMetaData) -> (bundleId: String, executablePath: String?) {
        let bundleId = metaData.sourceAppSigningIdentifier
        var executablePath: String? = nil
        
        // Try to get executable path from audit token if available
        if let auditToken = metaData.sourceAppAuditToken {
            executablePath = getExecutablePath(from: auditToken)
        }
        
        return (bundleId, executablePath)
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
        
        self.setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }
    
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }
    
    private var udpTCPConnections: [NEAppProxyUDPFlow: NWTCPConnection] = [:]
    private let tcpConnectionsLock = NSLock()
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let message = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let action = message["action"] as? String else {
            completionHandler?(nil)
            return
        }
        
        switch action {
        case "getLogs":
            logQueueLock.lock()
            if !logQueue.isEmpty {
                let logsToSend = Array(logQueue.prefix(min(100, logQueue.count)))
                logQueue.removeFirst(logsToSend.count)
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
        case "setProxyConfig":
            if let proxyType = message["proxyType"] as? String,
               let proxyHost = message["proxyHost"] as? String,
               let proxyPort = message["proxyPort"] as? Int {
                
                proxyLock.lock()
                self.proxyType = proxyType
                self.proxyHost = proxyHost
                self.proxyPort = proxyPort
                self.proxyUsername = message["proxyUsername"] as? String
                self.proxyPassword = message["proxyPassword"] as? String
                proxyLock.unlock()
                
                var logMsg = "Proxy config: \(proxyType)://\(proxyHost):\(proxyPort)"
                if let username = message["proxyUsername"] as? String {
                    logMsg += " (auth: \(username):***)"
                }
                log(logMsg)
            }
            let response = ["status": "ok"]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        
        case "addRule":
            if let ruleData = try? JSONSerialization.data(withJSONObject: message),
               var rule = try? JSONDecoder().decode(ProxyRule.self, from: ruleData) {
                rulesLock.lock()
                rule.ruleId = nextRuleId
                nextRuleId += 1
                rules.append(rule)
                rulesLock.unlock()
                
                log("Added rule #\(rule.ruleId): \(rule.processNames) -> \(rule.action.rawValue)")
                
                let response: [String: Any] = [
                    "status": "ok",
                    "ruleId": rule.ruleId,
                    "processNames": rule.processNames,
                    "targetHosts": rule.targetHosts,
                    "targetPorts": rule.targetPorts,
                    "protocol": rule.ruleProtocol.rawValue,
                    "action": rule.action.rawValue,
                    "enabled": rule.enabled
                ]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            } else {
                let response = ["status": "error", "message": "Invalid rule format"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            }
        
        case "updateRule":
            if let ruleId = message["ruleId"] as? UInt32,
               let ruleData = try? JSONSerialization.data(withJSONObject: message),
               let updatedRule = try? JSONDecoder().decode(ProxyRule.self, from: ruleData) {
                rulesLock.lock()
                if let index = rules.firstIndex(where: { $0.ruleId == ruleId }) {
                    var rule = updatedRule
                    rule.ruleId = ruleId
                    rules[index] = rule
                    rulesLock.unlock()
                    log("Updated rule #\(ruleId): \(rule.processNames) -> \(rule.action.rawValue)")
                    let response: [String: Any] = ["status": "ok", "ruleId": ruleId]
                    completionHandler?(try? JSONSerialization.data(withJSONObject: response))
                } else {
                    rulesLock.unlock()
                    let response = ["status": "error", "message": "Rule not found"]
                    completionHandler?(try? JSONSerialization.data(withJSONObject: response))
                }
            } else {
                let response = ["status": "error", "message": "Invalid update data"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            }
        
        case "toggleRule":
            if let ruleId = message["ruleId"] as? UInt32,
               let enabled = message["enabled"] as? Bool {
                rulesLock.lock()
                if let index = rules.firstIndex(where: { $0.ruleId == ruleId }) {
                    rules[index].enabled = enabled
                    rulesLock.unlock()
                    log("Rule #\(ruleId) \(enabled ? "enabled" : "disabled")")
                    let response: [String: Any] = ["status": "ok", "ruleId": ruleId, "enabled": enabled]
                    completionHandler?(try? JSONSerialization.data(withJSONObject: response))
                } else {
                    rulesLock.unlock()
                    let response = ["status": "error", "message": "Rule not found"]
                    completionHandler?(try? JSONSerialization.data(withJSONObject: response))
                }
            } else {
                let response = ["status": "error", "message": "Missing ruleId or enabled"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            }
        
        case "removeRule":
            if let ruleId = message["ruleId"] as? UInt32 {
                rulesLock.lock()
                let beforeCount = rules.count
                rules.removeAll { $0.ruleId == ruleId }
                let removed = beforeCount - rules.count
                rulesLock.unlock()
                log("Removed rule #\(ruleId)")
                let response: [String: Any] = ["status": "ok", "removed": removed]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            } else {
                let response = ["status": "error", "message": "Missing ruleId"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: response))
            }
        
        case "listRules":
            rulesLock.lock()
            let rulesList = rules.map { rule -> [String: Any] in
                return [
                    "ruleId": rule.ruleId,
                    "processNames": rule.processNames,
                    "targetHosts": rule.targetHosts,
                    "targetPorts": rule.targetPorts,
                    "protocol": rule.ruleProtocol.rawValue,
                    "action": rule.action.rawValue,
                    "enabled": rule.enabled
                ]
            }
            rulesLock.unlock()
            let response: [String: Any] = ["status": "ok", "rules": rulesList]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        
        case "clearRules":
            rulesLock.lock()
            let count = rules.count
            rules.removeAll()
            rulesLock.unlock()
            log("Cleared all rules (\(count) rules)")
            let response: [String: Any] = ["status": "ok", "cleared": count]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        
        case "setRules":
            if let rules = message["rules"] as? [[String: String]] {
                log("Rules updated: \(rules.count) rules")
            }
            let response = ["status": "ok"]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
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
        // Let all other traffic pass through directly
        return false
    }
    
    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow) -> Bool {
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
        
        var processIdentifier = "unknown"
        var executablePath: String? = nil
        
        if let metaData = flow.metaData as? NEFlowMetaData {
            let identifiers = getProcessIdentifiers(from: metaData)
            processIdentifier = identifiers.bundleId
            executablePath = identifiers.executablePath
        }
        
        // Use executable path for logging/display if available, otherwise use bundle ID
        let displayIdentifier = executablePath ?? processIdentifier
        
        if processIdentifier == "com.interceptsuite.ProxyBridge" || processIdentifier == "com.interceptsuite.ProxyBridge.extension" {
            return false
        }
        
        proxyLock.lock()
        let hasProxyConfig = (proxyHost != nil && proxyPort != nil)
        proxyLock.unlock()
        
        if !hasProxyConfig {
            sendLogToApp(protocol: "TCP", process: displayIdentifier, destination: destination, port: portStr, proxy: "Direct")
            return false
        }
        
        let matchedRule = findMatchingRule(bundleId: processIdentifier, executablePath: executablePath, destination: destination, port: portNum, connectionProtocol: .tcp, checkIpPort: true)
        
        if let rule = matchedRule {
            let action = rule.action.rawValue
            
            sendLogToApp(protocol: "TCP", process: displayIdentifier, destination: destination, port: portStr, proxy: action)
            
            switch rule.action {
            case .direct:
                return false
            case .block:
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return true
            case .proxy:
                proxyTCPFlow(flow, destination: destination, port: portNum)
                return true
            }
        } else {
            sendLogToApp(protocol: "TCP", process: displayIdentifier, destination: destination, port: portStr, proxy: "Direct")
            return false
        }
    }
    
    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
        var processIdentifier = "unknown"
        var executablePath: String? = nil
        
        if let metaData = flow.metaData as? NEFlowMetaData {
            let identifiers = getProcessIdentifiers(from: metaData)
            processIdentifier = identifiers.bundleId
            executablePath = identifiers.executablePath
        }
        
        // Use executable path for logging/display if available, otherwise use bundle ID
        let displayIdentifier = executablePath ?? processIdentifier
        
        if processIdentifier == "com.interceptsuite.ProxyBridge" || processIdentifier == "com.interceptsuite.ProxyBridge.extension" {
            return false
        }
        
        proxyLock.lock()
        let hasSOCKS5Proxy = (proxyHost != nil && proxyPort != nil && proxyType?.lowercased() == "socks5")
        let socksHost = self.proxyHost
        let socksPort = self.proxyPort
        proxyLock.unlock()
        
        if !hasSOCKS5Proxy {
            return false
        }
        
        let matchedRule = findMatchingRule(bundleId: processIdentifier, executablePath: executablePath, destination: "", port: 0, connectionProtocol: .udp, checkIpPort: false)
        
        if let rule = matchedRule {
            // We don't have access to UDP dest ip and port when os handles it in (apple proxy API limitation), we log with unknown ip and port to know specific package is using UDP
            switch rule.action {
            case .direct:
                sendLogToApp(protocol: "UDP", process: displayIdentifier, destination: "unknown", port: "unknown", proxy: "Direct")
                return false
            case .block:
                sendLogToApp(protocol: "UDP", process: displayIdentifier, destination: "unknown", port: "unknown", proxy: "BLOCK")
                return true
            case .proxy:
                flow.open(withLocalEndpoint: nil) { [weak self] error in
                    guard let self = self else { return }
                    
                    if let error = error {
                        self.log("Failed to open UDP flow: \(error.localizedDescription)", level: "ERROR")
                        return
                    }
                    
                    if let host = socksHost, let port = socksPort {
                        self.proxyUDPFlowViaSOCKS5(flow, processPath: displayIdentifier, socksHost: host, socksPort: port)
                    }
                }
                return true
            }
        } else {
            // No rule matched let OS handle it, but log it so user knows this process is using UDP
            sendLogToApp(protocol: "UDP", process: displayIdentifier, destination: "unknown", port: "unknown", proxy: "Direct")
            return false
        }
    }
    
    private func proxyUDPFlowViaSOCKS5(_ clientFlow: NEAppProxyUDPFlow, processPath: String, socksHost: String, socksPort: Int) {
        let proxyEndpoint = NWHostEndpoint(hostname: socksHost, port: String(socksPort))
        let tcpConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        
        let greeting: [UInt8] = [0x05, 0x01, 0x00]
        let greetingData = Data(greeting)
        
        tcpConnection.write(greetingData) { [weak self] error in
            guard let self = self else { return }
            
            if let error = error {
                self.log("SOCKS5 UDP greeting failed: \(error.localizedDescription)", level: "ERROR")
                return
            }
            
            tcpConnection.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("SOCKS5 UDP greeting response failed: \(error.localizedDescription)", level: "ERROR")
                    return
                }
                
                guard let data = data, data.count == 2, data[1] == 0x00 else {
                    self.log("SOCKS5 UDP greeting response failed", level: "ERROR")
                    return
                }
                
                self.sendSOCKS5UDPAssociate(clientFlow: clientFlow, tcpConnection: tcpConnection, processPath: processPath)
            }
        }
    }
    
    private func sendSOCKS5UDPAssociate(clientFlow: NEAppProxyUDPFlow, tcpConnection: NWTCPConnection, processPath: String) {
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
                self.log("SOCKS5 UDP ASSOCIATE failed: \(error.localizedDescription)", level: "ERROR")
                return
            }
            
            tcpConnection.readMinimumLength(10, maximumLength: 512) { [weak self] data, error in
                guard let self = self else { return }
                
                if let error = error {
                    self.log("SOCKS5 UDP ASSOCIATE response error: \(error.localizedDescription)", level: "ERROR")
                    return
                }
                
                guard let data = data, data.count >= 10, data[0] == 0x05, data[1] == 0x00 else {
                    self.log("SOCKS5 UDP ASSOCIATE rejected", level: "ERROR")
                    return
                }
                
                let (relayHost, relayPort) = self.parseSOCKS5Address(from: data, offset: 3)
                self.relayUDPThroughSOCKS5(clientFlow: clientFlow, relayHost: relayHost, relayPort: relayPort, tcpConnection: tcpConnection, processPath: processPath)
            }
        }
    }
    
    private func parseSOCKS5Address(from data: Data, offset: Int) -> (String, UInt16) {
        let atyp = data[offset]
        
        if atyp == 0x01 {
            let ip = "\(data[offset+1]).\(data[offset+2]).\(data[offset+3]).\(data[offset+4])"
            let port = (UInt16(data[offset+5]) << 8) | UInt16(data[offset+6])
            return (ip, port)
        } else if atyp == 0x04 {
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
            let len = Int(data[offset+1])
            let domain = String(data: data[(offset+2)..<(offset+2+len)], encoding: .utf8) ?? "unknown"
            let port = (UInt16(data[offset+2+len]) << 8) | UInt16(data[offset+2+len+1])
            return (domain, port)
        }
        
        return ("0.0.0.0", 0)
    }
    
    private func relayUDPThroughSOCKS5(clientFlow: NEAppProxyUDPFlow, relayHost: String, relayPort: UInt16, tcpConnection: NWTCPConnection, processPath: String) {
        let relayEndpoint = NWHostEndpoint(hostname: relayHost, port: String(relayPort))
        let udpSession = self.createUDPSession(to: relayEndpoint, from: nil)
        
        tcpConnectionsLock.lock()
        udpTCPConnections[clientFlow] = tcpConnection
        tcpConnectionsLock.unlock()
        
        readAndForwardClientUDP(clientFlow: clientFlow, udpSession: udpSession, processPath: processPath)
        readAndForwardRelayUDP(clientFlow: clientFlow, udpSession: udpSession)
    }
    
    private func readAndForwardClientUDP(clientFlow: NEAppProxyUDPFlow, udpSession: NWUDPSession, processPath: String) {
        var isFirstPacket = true
        
        clientFlow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }
            
            if let error = error {
                self.log("UDP read error: \(error.localizedDescription)", level: "ERROR")
                return
            }
            
            guard let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else {
                self.readAndForwardClientUDP(clientFlow: clientFlow, udpSession: udpSession, processPath: processPath)
                return
            }
            
            for i in 0..<datagrams.count {
                let datagram = datagrams[i]
                let endpoint = endpoints[i]
                
                var destHost = ""
                var destPort: UInt16 = 0
                var portStr = ""
                
                if let nwHost = endpoint as? NWHostEndpoint {
                    destHost = nwHost.hostname
                    destPort = UInt16(nwHost.port) ?? 0
                    portStr = nwHost.port
                }
                
                if isFirstPacket {
                    isFirstPacket = false
                    self.sendLogToApp(protocol: "UDP", process: processPath, destination: destHost, port: portStr, proxy: "SOCKS5")
                }
                
                if let encapsulated = self.encapsulateSOCKS5UDP(datagram: datagram, destHost: destHost, destPort: destPort) {
                    udpSession.writeDatagram(encapsulated, completionHandler: { error in
                        if let error = error {
                            self.log("UDP write error: \(error)", level: "ERROR")
                        }
                    })
                }
            }
            
            self.readAndForwardClientUDP(clientFlow: clientFlow, udpSession: udpSession, processPath: processPath)
        }
    }
    
    private func readAndForwardRelayUDP(clientFlow: NEAppProxyUDPFlow, udpSession: NWUDPSession) {
        udpSession.setReadHandler({ [weak self] datagrams, error in
            guard let self = self else { return }
            
            if let error = error {
                self.log("UDP relay error: \(error.localizedDescription)", level: "ERROR")
                return
            }
            
            if let datagrams = datagrams, !datagrams.isEmpty {
                var unwrappedDatagrams: [Data] = []
                var unwrappedEndpoints: [NWEndpoint] = []
                
                for datagram in datagrams {
                    if let (unwrapped, destHost, destPort) = self.decapsulateSOCKS5UDPWithEndpoint(datagram: datagram) {
                        unwrappedDatagrams.append(unwrapped)
                        unwrappedEndpoints.append(NWHostEndpoint(hostname: destHost, port: String(destPort)))
                    }
                }
                
                if !unwrappedDatagrams.isEmpty {
                    clientFlow.writeDatagrams(unwrappedDatagrams, sentBy: unwrappedEndpoints) { error in
                        if let error = error {
                            self.log("UDP response write error: \(error.localizedDescription)", level: "ERROR")
                        }
                    }
                }
            }
        }, maxDatagrams: 32)
    }
    
    private func encapsulateSOCKS5UDP(datagram: Data, destHost: String, destPort: UInt16) -> Data? {
        if datagram.count > 1400 {
            self.log("Datagram too large (\(datagram.count) bytes), skipping", level: "WARN")
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
            guard destHost.count <= 255 else {
                self.log("Domain name too long: \(destHost.count) bytes", level: "ERROR")
                return nil
            }
            header.append(0x03)
            header.append(UInt8(destHost.count))
            header.append(destHost.data(using: .utf8) ?? Data())
        }
        
        header.append(UInt8(destPort >> 8))
        header.append(UInt8(destPort & 0xFF))
        
        var result = header
        result.append(datagram)
        
        if result.count > 1472 {
            self.log("Encapsulated datagram too large (\(result.count) bytes), skipping", level: "WARN")
            return nil
        }
        
        return result
    }
    
    private func decapsulateSOCKS5UDP(datagram: Data) -> Data? {
        guard datagram.count > 10 else { return nil }
        
        let atyp = datagram[3]
        var headerLen = 4
        
        if atyp == 0x01 {
            headerLen += 6
        } else if atyp == 0x04 {
            headerLen += 18
        } else if atyp == 0x03 {
            let domainLen = Int(datagram[4])
            headerLen += 1 + domainLen + 2
        } else {
            return nil
        }
        
        guard datagram.count > headerLen else { return nil }
        
        return datagram[headerLen...]
    }
    
    private func decapsulateSOCKS5UDPWithEndpoint(datagram: Data) -> (Data, String, UInt16)? {
        guard datagram.count > 10 else { return nil }
        
        let atyp = datagram[3]
        var headerLen = 4
        var destHost = ""
        var destPort: UInt16 = 0
        
        if atyp == 0x01 {
            destHost = "\(datagram[4]).\(datagram[5]).\(datagram[6]).\(datagram[7])"
            destPort = (UInt16(datagram[8]) << 8) | UInt16(datagram[9])
            headerLen += 6
        } else if atyp == 0x04 {
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
            let domainLen = Int(datagram[4])
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
    
    private func proxyTCPFlow(_ flow: NEAppProxyTCPFlow, destination: String, port: UInt16) {
        proxyLock.lock()
        guard let proxyHost = self.proxyHost,
              let proxyPort = self.proxyPort,
              let proxyType = self.proxyType else {
            proxyLock.unlock()
            log("Proxy config missing", level: "ERROR")
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }
        let username = self.proxyUsername
        let password = self.proxyPassword
        proxyLock.unlock()
        
        let proxyEndpoint = NWHostEndpoint(hostname: proxyHost, port: String(proxyPort))
        let proxyConnection = createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        
        proxyConnection.addObserver(self, forKeyPath: "state", options: .new, context: nil)
        
        if proxyType.lowercased() == "socks5" {
            handleSOCKS5Proxy(clientFlow: flow, proxyConnection: proxyConnection, destination: destination, port: port, username: username, password: password)
        } else if proxyType.lowercased() == "http" {
            handleHTTPProxy(clientFlow: flow, proxyConnection: proxyConnection, destination: destination, port: port, username: username, password: password)
        } else {
            log("Unsupported proxy type: \(proxyType)", level: "ERROR")
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
        var authData = Data()
        authData.append(0x01)
        authData.append(UInt8(username.count))
        authData.append(username.data(using: .utf8) ?? Data())
        authData.append(UInt8(password.count))
        authData.append(password.data(using: .utf8) ?? Data())
        
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
            request.append(0x03)
            request.append(UInt8(destination.count))
            request.append(destination.data(using: .utf8) ?? Data())
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
                
                self.log("SOCKS5 connection established to \(destination):\(port)")
                self.relayData(clientFlow: clientFlow, proxyConnection: proxyConnection)
            }
        }
    }
    
    private func handleHTTPProxy(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection, destination: String, port: UInt16, username: String?, password: String?) {
        var request = "CONNECT \(destination):\(port) HTTP/1.1\r\n"
        request += "Host: \(destination):\(port)\r\n"
        
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
                    self.log("HTTP CONNECT established to \(destination):\(port)")
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
        clientFlow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.log("Failed to open client flow: \(error.localizedDescription)", level: "ERROR")
                proxyConnection.cancel()
                return
            }
            
            self?.relayClientToProxy(clientFlow: clientFlow, proxyConnection: proxyConnection)
            self?.relayProxyToClient(clientFlow: clientFlow, proxyConnection: proxyConnection)
        }
    }
    
    private func relayClientToProxy(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection) {
        clientFlow.readData { [weak self] data, error in
            if let error = error {
                self?.log("Client read error: \(error.localizedDescription)", level: "ERROR")
                proxyConnection.cancel()
                return
            }
            
            guard let data = data, !data.isEmpty else {
                self?.log("Client closed connection")
                proxyConnection.cancel()
                return
            }
            
            proxyConnection.write(data) { error in
                if let error = error {
                    self?.log("Proxy write error: \(error.localizedDescription)", level: "ERROR")
                    clientFlow.closeReadWithError(error)
                    clientFlow.closeWriteWithError(error)
                } else {
                    self?.relayClientToProxy(clientFlow: clientFlow, proxyConnection: proxyConnection)
                }
            }
        }
    }
    
    private func relayProxyToClient(clientFlow: NEAppProxyTCPFlow, proxyConnection: NWTCPConnection) {
        proxyConnection.readMinimumLength(1, maximumLength: 65536) { [weak self] data, error in
            if let error = error {
                self?.log("Proxy read error: \(error.localizedDescription)", level: "ERROR")
                clientFlow.closeReadWithError(error)
                clientFlow.closeWriteWithError(error)
                return
            }
            
            guard let data = data, !data.isEmpty else {
                self?.log("Proxy closed connection")
                clientFlow.closeReadWithError(nil)
                clientFlow.closeWriteWithError(nil)
                return
            }
            
            clientFlow.write(data) { error in
                if let error = error {
                    self?.log("Client write error: \(error.localizedDescription)", level: "ERROR")
                    proxyConnection.cancel()
                } else {
                    self?.relayProxyToClient(clientFlow: clientFlow, proxyConnection: proxyConnection)
                }
            }
        }
    }
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
    }
    
    private func findMatchingRule(bundleId: String, executablePath: String?, destination: String, port: UInt16, connectionProtocol: RuleProtocol, checkIpPort: Bool) -> ProxyRule? {
        rulesLock.lock()
        defer { rulesLock.unlock() }
        
        for rule in rules {
            guard rule.enabled else { continue }
            
            if rule.ruleProtocol != .both && rule.ruleProtocol != connectionProtocol {
                continue
            }
            
            // Try matching against executable path first (if available), then bundle ID
            let processMatched = executablePath.map { rule.matchesProcess($0) } ?? false || rule.matchesProcess(bundleId)
            
            if !processMatched {
                continue
            }
            
            if checkIpPort {
                if !rule.matchesIP(destination) {
                    continue
                }
                
                if !rule.matchesPort(port) {
                    continue
                }
            }
            
            return rule
        }
        
        return nil
    }
    
    private func sendLogToApp(protocol: String, process: String, destination: String, port: String, proxy: String) {
        guard trafficLoggingEnabled else { return }
        
        let logData: [String: String] = [
            "type": "connection",
            "protocol": `protocol`,
            "process": process,
            "destination": destination,
            "port": port,
            "proxy": proxy
        ]
        
        logQueueLock.lock()
        logQueue.append(logData)
        if logQueue.count > 1000 {
            logQueue.removeFirst()
        }
        logQueueLock.unlock()
    }
}



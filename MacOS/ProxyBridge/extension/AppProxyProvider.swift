//
//  AppProxyProvider.swift
//  extension
//
//  Created by sourav kalal on 13/11/25.
//

import NetworkExtension

// MARK: - Rule Definitions
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
    
    private var rules: [ProxyRule] = []
    private let rulesLock = NSLock()
    private var nextRuleId: UInt32 = 1
    
    private var proxyType: String?
    private var proxyHost: String?
    private var proxyPort: Int?
    private var proxyUsername: String?
    private var proxyPassword: String?
    private let proxyLock = NSLock()
    
    // MARK: - Logging Helper
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
                let logEntry = logQueue.removeFirst()
                logQueueLock.unlock()
                completionHandler?(try? JSONSerialization.data(withJSONObject: logEntry))
            } else {
                logQueueLock.unlock()
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
        }
        // Let all traffic pass through directly
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
        
        var processPath = "unknown"
        if let metaData = flow.metaData as? NEFlowMetaData {
            processPath = metaData.sourceAppSigningIdentifier
        }
        
        // Check if proxy is configured
        proxyLock.lock()
        let hasProxyConfig = (proxyHost != nil && proxyPort != nil)
        proxyLock.unlock()
        
        if !hasProxyConfig {
            sendLogToApp(protocol: "TCP", process: processPath, destination: destination, port: portStr, proxy: "Direct")
            return false
        }
        
        let matchedRule = findMatchingRule(processPath: processPath, destination: destination, port: portNum, connectionProtocol: .tcp)
        
        if let rule = matchedRule {
            let action = rule.action.rawValue
            log("Rule #\(rule.ruleId) matched: \(processPath) -> \(destination):\(portStr) -> \(action)")
            
            sendLogToApp(protocol: "TCP", process: processPath, destination: destination, port: portStr, proxy: action)
            
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
            sendLogToApp(protocol: "TCP", process: processPath, destination: destination, port: portStr, proxy: "Direct")
            return false
        }
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
            
            // Read server response (2 bytes: version, chosen method)
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
                    // No authentication required
                    self.sendSOCKS5ConnectRequest(clientFlow: clientFlow, proxyConnection: proxyConnection, destination: destination, port: port)
                } else if method == 0x02 {
                    // Username/password authentication required
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
        // Auth format: [Version(1), Username length, Username, Password length, Password]
        var authData = Data()
        authData.append(0x01) // Auth version
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
            
            // Read auth response (2 bytes: version, status)
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
            
            // Read connect response (minimum 10 bytes)
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
            
            // Read HTTP response
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
                    // Continue reading from client
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
                    // Continue reading from proxy
                    self?.relayProxyToClient(clientFlow: clientFlow, proxyConnection: proxyConnection)
                }
            }
        }
    }
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
    }
    
    private func findMatchingRule(processPath: String, destination: String, port: UInt16, connectionProtocol: RuleProtocol) -> ProxyRule? {
        rulesLock.lock()
        defer { rulesLock.unlock() }
        
        for rule in rules {
            guard rule.enabled else { continue }
            
            if rule.ruleProtocol != .both && rule.ruleProtocol != connectionProtocol {
                continue
            }
            
            if !rule.matchesProcess(processPath) {
                continue
            }
            
            if !rule.matchesIP(destination) {
                continue
            }
            
            if !rule.matchesPort(port) {
                continue
            }
            
            return rule
        }
        
        return nil
    }
    
    private func sendLogToApp(protocol: String, process: String, destination: String, port: String, proxy: String) {
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



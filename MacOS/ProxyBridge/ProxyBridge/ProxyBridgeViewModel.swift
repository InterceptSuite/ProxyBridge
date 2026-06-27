import Foundation
import NetworkExtension
import SystemExtensions
import Combine

class ProxyBridgeViewModel: NSObject, ObservableObject {
    @Published var connections: [ConnectionLog] = []
    @Published var activityLogs: [ActivityLog] = []
    @Published var isProxyActive = false
    @Published var isTrafficLoggingEnabled = true
    
    var tunnelSession: NETunnelProviderSession?
    private var logTimer: Timer?
    @Published private(set) var proxyConfigs: [ProxyConfig] = []
    
    private let maxLogEntries = 1000
    // trim to 80% when limit hit to avoid trimming on each entry
    private let trimToEntries = 800
    private let logPollingInterval = 1.0
    private let extensionIdentifier = "com.interceptsuite.ProxyBridge.extension"
    // reuse formatter
    // saves memory about 2% and speed up the ui
    private let timestampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
    // removed uuid and use int - memory usage and speed improved due to size
    private var connectionIdCounter: Int = 0
    private var activityIdCounter: Int = 0
    
    struct ProxyConfig: Identifiable, Codable {
        let id: String
        let type: String
        let host: String
        let port: Int
        let username: String?
        let password: String?

        var displayName: String { "\(type.uppercased()) \(host):\(port)" }

        init(id: String = UUID().uuidString, type: String, host: String, port: Int, username: String?, password: String?) {
            self.id = id
            self.type = type
            self.host = host
            self.port = port
            self.username = username
            self.password = password
        }
    }
    
    struct ConnectionLog: Identifiable {
        let id: Int
        let timestamp: String
        let connectionProtocol: String
        let process: String
        let destination: String
        let port: String
        let proxy: String
    }
    
    struct ActivityLog: Identifiable {
        let id: Int
        let timestamp: String
        let level: String
        let message: String
    }
    
    override init() {
        super.init()
        loadTrafficLoggingSetting()
        loadProxyConfig()
        installAndStartProxy()
    }
    
    private func loadTrafficLoggingSetting() {
        isTrafficLoggingEnabled = UserDefaults.standard.object(forKey: "trafficLoggingEnabled") as? Bool ?? true
    }
    
    func toggleTrafficLogging() {
        isTrafficLoggingEnabled.toggle()
        UserDefaults.standard.set(isTrafficLoggingEnabled, forKey: "trafficLoggingEnabled")
        sendTrafficLoggingToExtension(isTrafficLoggingEnabled)
        
        if isTrafficLoggingEnabled {
            startLogPollingTimer()
        } else {
            logTimer?.invalidate()
            logTimer = nil
        }
    }
    
    private func sendTrafficLoggingToExtension(_ enabled: Bool) {
        guard let session = tunnelSession else { return }
        
        let message: [String: Any] = [
            "action": "setTrafficLogging",
            "enabled": enabled
        ]
        
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
        
        try? session.sendProviderMessage(data) { _ in }
    }
    
    private func loadProxyConfig() {
        if let data = UserDefaults.standard.data(forKey: "proxyConfigs"),
           let configs = try? JSONDecoder().decode([ProxyConfig].self, from: data) {
            proxyConfigs = configs
        }
    }

    private func saveProxyConfigs() {
        if let data = try? JSONEncoder().encode(proxyConfigs) {
            UserDefaults.standard.set(data, forKey: "proxyConfigs")
        }
    }

    func addProxyConfig(_ config: ProxyConfig) {
        proxyConfigs.append(config)
        saveProxyConfigs()
        if let session = tunnelSession {
            sendProxyConfigsToExtension(session: session)
        }
    }

    func updateProxyConfig(_ config: ProxyConfig) {
        if let index = proxyConfigs.firstIndex(where: { $0.id == config.id }) {
            proxyConfigs[index] = config
            saveProxyConfigs()
            if let session = tunnelSession {
                sendProxyConfigsToExtension(session: session)
            }
        }
    }

    func rulesUsingProxy(id: String) -> Int {
        let saved = UserDefaults.standard.array(forKey: "proxyRules") as? [[String: Any]] ?? []
        return saved.filter { ($0["action"] as? String) == id }.count
    }

    func removeProxyConfig(_ config: ProxyConfig) {
        // reset any rules pointing to this config to DIRECT so they don't silently go direct anyway
        if var saved = UserDefaults.standard.array(forKey: "proxyRules") as? [[String: Any]] {
            var changed = false
            for i in saved.indices where (saved[i]["action"] as? String) == config.id {
                saved[i]["action"] = "DIRECT"
                changed = true
            }
            if changed {
                UserDefaults.standard.set(saved, forKey: "proxyRules")
                if let session = tunnelSession {
                    RuleManager.loadRulesFromUserDefaults(session: session) { _, _ in }
                }
            }
        }
        proxyConfigs.removeAll { $0.id == config.id }
        saveProxyConfigs()
        if let session = tunnelSession {
            sendProxyConfigsToExtension(session: session)
        }
    }
    
    private func installAndStartProxy() {
        // Stop any existing tunnel first so macOS replaces the running extension
        // binary with the newly installed one instead of reusing the old cached process.
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let existing = managers?.first,
               let session = existing.connection as? NETunnelProviderSession,
               session.status != .disconnected && session.status != .invalid {
                session.stopTunnel()
                // Brief pause to let the old extension fully terminate
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                    self.submitExtensionActivationRequest()
                }
            } else {
                self.submitExtensionActivationRequest()
            }
        }
    }
    
    private func submitExtensionActivationRequest() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
    
    func startProxy() {
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                self.addLog("ERROR", "Failed to load managers: \(error.localizedDescription)")
                return
            }
            
            let manager = managers?.first ?? NETransparentProxyManager()
            manager.localizedDescription = "ProxyBridge Transparent Proxy"
            manager.isEnabled = true
            
            let providerProtocol = NETunnelProviderProtocol()
            providerProtocol.providerBundleIdentifier = self.extensionIdentifier
            providerProtocol.serverAddress = "ProxyBridge"
            manager.protocolConfiguration = providerProtocol
            
            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    self.addLog("ERROR", "Failed to save preferences: \(saveError.localizedDescription)")
                    return
                }
                
                self.addLog("INFO", "Configuration saved")
                self.reloadAndStartTunnel(manager: manager)
            }
        }
    }
    
    private func reloadAndStartTunnel(manager: NETransparentProxyManager) {
        manager.loadFromPreferences { [weak self] loadError in
            guard let self = self else { return }

            if let loadError = loadError {
                self.addLog("ERROR", "Failed to reload preferences: \(loadError.localizedDescription)")
                return
            }

            guard let session = manager.connection as? NETunnelProviderSession else { return }

            // register before startTunnel so we can't miss a fast .connected transition
            // remove the observer the moment it fires in oneshot to avoid configuring twice
            var observer: NSObjectProtocol?
            observer = NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange,
                object: session,
                queue: .main
            ) { [weak self] _ in
                guard let self = self, session.status == .connected else { return }
                if let obs = observer { NotificationCenter.default.removeObserver(obs) }
                observer = nil

                self.setupLogPolling(session: session)
                if !self.proxyConfigs.isEmpty {
                    self.sendProxyConfigsToExtension(session: session)
                }
                
                RuleManager.loadRulesFromUserDefaults(session: session) { success, count in
                    if success && count > 0 {
                        self.addLog("INFO", "Loaded \(count) rule(s) from local storage")
                    }
                }
            }

            do {
                try session.startTunnel()
                DispatchQueue.main.async {
                    self.isProxyActive = true
                    self.addLog("INFO", "Proxy tunnel started")
                }
            } catch {
                if let obs = observer { NotificationCenter.default.removeObserver(obs) }
                observer = nil
                self.addLog("ERROR", "Failed to start tunnel: \(error.localizedDescription)")
            }
        }
    }
    
    func stopProxy() {
        guard let session = tunnelSession else {
            isProxyActive = false
            logTimer?.invalidate()
            logTimer = nil
            return
        }
        
        // Clear all data from extension memory before stopping
        clearExtensionMemory(session: session) { [weak self] in
            guard let self = self else { return }
            
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                if let manager = managers?.first {
                    (manager.connection as? NETunnelProviderSession)?.stopTunnel()
                    self.isProxyActive = false
                    self.logTimer?.invalidate()
                    self.logTimer = nil
                    self.tunnelSession = nil
                    self.addLog("INFO", "Proxy stopped and extension memory cleared")
                }
            }
        }
    }
    
    private func clearExtensionMemory(session: NETunnelProviderSession, completion: @escaping () -> Void) {
        // clear rules auto fix the #51 - and proxy rules become inactive after It closes
        RuleManager.clearRules(session: session) { success, message in
            //clear proxy config as well keep meory usage low for extesion 
            let clearConfigMessage: [String: Any] = [
                "action": "clearConfig"
            ]
            
            guard let data = try? JSONSerialization.data(withJSONObject: clearConfigMessage) else {
                completion()
                return
            }
            
            try? session.sendProviderMessage(data) { _ in
                completion()
            }
        }
    }
    
    private func setupLogPolling(session: NETunnelProviderSession) {
        tunnelSession = session
        
        sendTrafficLoggingToExtension(isTrafficLoggingEnabled)
        
        if isTrafficLoggingEnabled {
            startLogPollingTimer()
        }
    }
    
    private func startLogPollingTimer() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.logTimer?.invalidate()
            self.logTimer = Timer.scheduledTimer(
                withTimeInterval: self.logPollingInterval,
                repeats: true
            ) { [weak self] _ in
                self?.pollLogs()
            }
        }
    }
    
    private func pollLogs() {
        guard let session = tunnelSession else { return }
        
        let message = ["action": "getLogs"]
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
        
        try? session.sendProviderMessage(data) { [weak self] response in
            guard let self = self,
                  let responseData = response else {
                return
            }
            
            if let logs = try? JSONSerialization.jsonObject(with: responseData) as? [[String: String]] {
                DispatchQueue.main.async {
                    for log in logs {
                        if log["type"] == "connection" {
                            self.handleConnectionLog(log)
                        } else {
                            self.handleActivityLog(log)
                        }
                    }
                }
            }
        }
    }
    
    private func handleConnectionLog(_ log: [String: String]) {
        guard isTrafficLoggingEnabled else { return }
        
        guard let proto = log["protocol"],
              let process = log["process"],
              let dest = log["destination"],
              let port = log["port"],
              let proxy = log["proxy"] else {
            return
        }
        
        connectionIdCounter &+= 1
        let connectionLog = ConnectionLog(
            id: connectionIdCounter,
            timestamp: getCurrentTimestamp(),
            connectionProtocol: proto,
            process: process,
            destination: dest,
            port: port,
            proxy: proxy
        )
        connections.append(connectionLog)
        
        // Trim in bulk to avoid O(n) shift on every entry at the limit
        if connections.count > maxLogEntries {
            connections.removeFirst(connections.count - trimToEntries)
        }
    }
    
    private func handleActivityLog(_ log: [String: String]) {
        guard let timestamp = log["timestamp"],
              let level = log["level"],
              let message = log["message"] else {
            return
        }
        
        activityIdCounter &+= 1
        let activityLog = ActivityLog(
            id: activityIdCounter,
            timestamp: timestamp,
            level: level,
            message: message
        )
        activityLogs.append(activityLog)
        
        if activityLogs.count > maxLogEntries {
            activityLogs.removeFirst(activityLogs.count - trimToEntries)
        }
    }
    

    func sendProxyConfigsToExtension(session: NETunnelProviderSession) {
        let configsArray: [[String: Any]] = proxyConfigs.map { config in
            var dict: [String: Any] = [
                "id": config.id,
                "proxyType": config.type,
                "proxyHost": config.host,
                "proxyPort": config.port
            ]
            if let u = config.username { dict["proxyUsername"] = u }
            if let p = config.password { dict["proxyPassword"] = p }
            return dict
        }
        let message: [String: Any] = ["action": "setProxyConfigs", "configs": configsArray]
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            addLog("ERROR", "Failed to encode proxy configs")
            return
        }
        try? session.sendProviderMessage(data) { [weak self] response in
            if let responseData = response,
               let json = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
               let status = json["status"] as? String, status == "ok" {
                DispatchQueue.main.async {
                    self?.addLog("INFO", "Proxy configs sent: \(self?.proxyConfigs.count ?? 0) config(s)")
                }
            }
        }
    }
    
    func clearConnections() {
        connections.removeAll()
    }
    
    func clearActivityLogs() {
        activityLogs.removeAll()
    }
    
    private func addLog(_ level: String, _ message: String) {
        activityIdCounter &+= 1
        let log = ActivityLog(
            id: activityIdCounter,
            timestamp: getCurrentTimestamp(),
            level: level,
            message: message
        )
        activityLogs.append(log)
        
        if activityLogs.count > maxLogEntries {
            activityLogs.removeFirst(activityLogs.count - trimToEntries)
        }
    }
    
    private func getCurrentTimestamp() -> String {
        return timestampFormatter.string(from: Date())
    }
    
    deinit {
        logTimer?.invalidate()
        stopProxy()
    }
}

extension ProxyBridgeViewModel: OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        DispatchQueue.main.async {
            self.addLog("INFO", "Extension installed successfully")
            self.startProxy()
        }
    }
    
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        DispatchQueue.main.async {
            self.addLog("ERROR", "Extension failed: \(error.localizedDescription)")
        }
    }
    
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        DispatchQueue.main.async {
            self.addLog("INFO", "Extension needs user approval in System Settings")
        }
    }
    
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("Replacing existing extension")
        return .replace
    }
}

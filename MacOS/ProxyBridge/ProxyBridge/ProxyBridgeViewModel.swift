import Foundation
import NetworkExtension
import SystemExtensions
import Combine

class ProxyBridgeViewModel: NSObject, ObservableObject {
    @Published var connections: [ConnectionLog] = []
    @Published var activityLogs: [ActivityLog] = []
    @Published var isProxyActive = false
    
    var tunnelSession: NETunnelProviderSession?
    private var logTimer: Timer?
    private(set) var proxyConfig: ProxyConfig?
    
    private let maxLogEntries = 1000
    private let logPollingInterval = 0.1
    private let extensionIdentifier = "com.interceptsuite.ProxyBridge.extension"
    
    struct ProxyConfig {
        let type: String
        let host: String
        let port: Int
        let username: String?
        let password: String?
    }
    
    struct ConnectionLog: Identifiable {
        let id = UUID()
        let timestamp: String
        let connectionProtocol: String
        let process: String
        let destination: String
        let port: String
        let proxy: String
    }
    
    struct ActivityLog: Identifiable {
        let id = UUID()
        let timestamp: String
        let level: String
        let message: String
    }
    
    override init() {
        super.init()
        loadProxyConfig()
        installAndStartProxy()
    }
    
    private func loadProxyConfig() {
        if let type = UserDefaults.standard.string(forKey: "proxyType"),
           let host = UserDefaults.standard.string(forKey: "proxyHost"),
           let port = UserDefaults.standard.object(forKey: "proxyPort") as? Int {
            let username = UserDefaults.standard.string(forKey: "proxyUsername")
            let password = UserDefaults.standard.string(forKey: "proxyPassword")
            
            proxyConfig = ProxyConfig(
                type: type,
                host: host,
                port: port,
                username: username,
                password: password
            )
        }
    }
    
    private func saveProxyConfig(_ config: ProxyConfig) {
        UserDefaults.standard.set(config.type, forKey: "proxyType")
        UserDefaults.standard.set(config.host, forKey: "proxyHost")
        UserDefaults.standard.set(config.port, forKey: "proxyPort")
        
        if let username = config.username {
            UserDefaults.standard.set(username, forKey: "proxyUsername")
        } else {
            UserDefaults.standard.removeObject(forKey: "proxyUsername")
        }
        
        if let password = config.password {
            UserDefaults.standard.set(password, forKey: "proxyPassword")
        } else {
            UserDefaults.standard.removeObject(forKey: "proxyPassword")
        }
    }
    
    private func installAndStartProxy() {
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
            
            do {
                try (manager.connection as? NETunnelProviderSession)?.startTunnel()
                self.isProxyActive = true
                self.addLog("INFO", "Proxy tunnel started")
                
                if let session = manager.connection as? NETunnelProviderSession {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        self.setupLogPolling(session: session)
                        
                        if let config = self.proxyConfig {
                            self.sendProxyConfigToExtension(config, session: session)
                        }
                        
                        RuleManager.loadRulesFromUserDefaults(session: session) { success, count in
                            if success && count > 0 {
                                self.addLog("INFO", "Loaded \(count) rule(s) from local storage")
                            }
                        }
                    }
                }
            } catch {
                self.addLog("ERROR", "Failed to start tunnel: \(error.localizedDescription)")
            }
        }
    }
    
    func stopProxy() {
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let manager = managers?.first {
                (manager.connection as? NETunnelProviderSession)?.stopTunnel()
                self.isProxyActive = false
                self.logTimer?.invalidate()
                self.logTimer = nil
                self.addLog("INFO", "Proxy stopped")
            }
        }
    }
    
    private func setupLogPolling(session: NETunnelProviderSession) {
        tunnelSession = session
        
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
                  let responseData = response,
                  let log = try? JSONSerialization.jsonObject(with: responseData) as? [String: String] else {
                return
            }
            
            DispatchQueue.main.async {
                if log["type"] == "connection" {
                    self.handleConnectionLog(log)
                } else {
                    self.handleActivityLog(log)
                }                
            }
        }
    }
    
    private func handleConnectionLog(_ log: [String: String]) {
        guard let proto = log["protocol"],
              let process = log["process"],
              let dest = log["destination"],
              let port = log["port"],
              let proxy = log["proxy"] else {
            return
        }
        
        let connectionLog = ConnectionLog(
            timestamp: getCurrentTimestamp(),
            connectionProtocol: proto,
            process: process,
            destination: dest,
            port: port,
            proxy: proxy
        )
        connections.append(connectionLog)
        
        if connections.count > maxLogEntries {
            connections.removeFirst()
        }
    }
    
    private func handleActivityLog(_ log: [String: String]) {
        guard let timestamp = log["timestamp"],
              let level = log["level"],
              let message = log["message"] else {
            return
        }
        
        let activityLog = ActivityLog(
            timestamp: timestamp,
            level: level,
            message: message
        )
        activityLogs.append(activityLog)
        
        if activityLogs.count > maxLogEntries {
            activityLogs.removeFirst()
        }
    }
    
    func setProxyConfig(_ config: ProxyConfig) {
        proxyConfig = config
        saveProxyConfig(config)
        
        guard let session = tunnelSession else {
            addLog("ERROR", "Extension not connected")
            return
        }
        
        sendProxyConfigToExtension(config, session: session)
    }
    
    private func sendProxyConfigToExtension(_ config: ProxyConfig, session: NETunnelProviderSession) {
        var message: [String: Any] = [
            "action": "setProxyConfig",
            "proxyType": config.type,
            "proxyHost": config.host,
            "proxyPort": config.port
        ]
        
        if let username = config.username {
            message["proxyUsername"] = username
        }
        if let password = config.password {
            message["proxyPassword"] = password
        }
        
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            addLog("ERROR", "Failed to encode proxy config")
            return
        }
        
        try? session.sendProviderMessage(data) { [weak self] response in
            if let responseData = response,
               let json = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
               let status = json["status"] as? String, status == "ok" {
                DispatchQueue.main.async {
                    self?.addLog("INFO", "Proxy configured: \(config.type)://\(config.host):\(config.port)")
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
        let log = ActivityLog(
            timestamp: getCurrentTimestamp(),
            level: level,
            message: message
        )
        activityLogs.append(log)
        
        if activityLogs.count > maxLogEntries {
            activityLogs.removeFirst()
        }
    }
    
    private func getCurrentTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: Date())
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

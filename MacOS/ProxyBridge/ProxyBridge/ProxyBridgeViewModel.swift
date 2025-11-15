//
//  ProxyBridgeViewModel.swift
//  ProxyBridge - GUI ViewModel
//
//  Created by sourav kalal on 14/11/25.
//

import Foundation
import NetworkExtension
import SystemExtensions
import Combine

class ProxyBridgeViewModel: NSObject, ObservableObject {
    @Published var connections: [ConnectionLog] = []
    @Published var activityLogs: [ActivityLog] = []
    @Published var isProxyActive = false
    
    private var tunnelSession: NETunnelProviderSession?
    private var logTimer: Timer?
    private var proxyConfig: ProxyConfig?
    
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
        installAndStartProxy()
    }
    
    private func installAndStartProxy() {
        print("Installing system extension")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "com.interceptsuite.ProxyBridge.extension",
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
            providerProtocol.providerBundleIdentifier = "com.interceptsuite.ProxyBridge.extension"
            providerProtocol.serverAddress = "ProxyBridge"
            manager.protocolConfiguration = providerProtocol
            
            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    self.addLog("ERROR", "Failed to save preferences: \(saveError.localizedDescription)")
                    return
                }
                
                self.addLog("INFO", "Configuration saved")
                
                manager.loadFromPreferences { loadError in
                    if let loadError = loadError {
                        self.addLog("ERROR", "Failed to reload preferences: \(loadError.localizedDescription)")
                        return
                    }
                    
                    do {
                        try (manager.connection as? NETunnelProviderSession)?.startTunnel()
                        self.isProxyActive = true
                        self.addLog("INFO", "Proxy tunnel started")
                        
                        if let session = manager.connection as? NETunnelProviderSession {
                            // Wait a bit for extension to initialize
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                self.setupLogPolling(session: session)
                            }
                        }
                    } catch {
                        self.addLog("ERROR", "Failed to start tunnel: \(error.localizedDescription)")
                    }
                }
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
            self?.logTimer?.invalidate()
            self?.logTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
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
                // Connection log
                if let type = log["type"], type == "connection",
                   let proto = log["protocol"],
                   let process = log["process"],
                   let dest = log["destination"],
                   let port = log["port"],
                   let proxy = log["proxy"] {
                    
                    let connectionLog = ConnectionLog(
                        timestamp: self.getCurrentTimestamp(),
                        connectionProtocol: proto,
                        process: process,
                        destination: dest,
                        port: port,
                        proxy: proxy
                    )
                    self.connections.append(connectionLog)
                    
                    if self.connections.count > 1000 {
                        self.connections.removeFirst()
                    }
                }
                // Activity log
                else if let timestamp = log["timestamp"],
                        let level = log["level"],
                        let message = log["message"] {
                    
                    let activityLog = ActivityLog(
                        timestamp: timestamp,
                        level: level,
                        message: message
                    )
                    self.activityLogs.append(activityLog)
                    
                    if self.activityLogs.count > 1000 {
                        self.activityLogs.removeFirst()
                    }
                }
            }
        }
    }
    
    func setProxyConfig(_ config: ProxyConfig) {
        proxyConfig = config
        
        guard let session = tunnelSession else {
            addLog("ERROR", "Extension not connected")
            return
        }
        
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
        
        if activityLogs.count > 1000 {
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

//
//  ProxyBridgeApp.swift
//  ProxyBridge - CLI Tool
//
//  Created by sourav kalal on 13/11/25.
//

import Foundation
import NetworkExtension
import SystemExtensions
import os.log

@main
class ProxyBridgeApp: NSObject {
    
    static let shared = ProxyBridgeApp()
    private var shouldKeepRunning = true
    private let runLoop = CFRunLoopGetCurrent()
    private var tunnelSession: NETunnelProviderSession?
    private var statusObserver: NSObjectProtocol?
    private var proxyConfig: ProxyConfig?
    
    struct ProxyConfig {
        let type: String  // "socks5" or "http"
        let host: String
        let port: Int
        let username: String?
        let password: String?
    }
    
    static func main() {
        let app = ProxyBridgeApp.shared
        
        print("ProxyBridge CLI - Starting")
        
        // Parse command line arguments
        app.parseArguments()
        
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        
        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler {
            print("\nShutting down...")
            fflush(stdout)
            app.shouldKeepRunning = false
            app.shutdown()
            CFRunLoopStop(app.runLoop)
            exit(0)
        }
        sigintSource.resume()
        
        let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigtermSource.setEventHandler {
            print("\nTerminating...")
            fflush(stdout)
            app.shouldKeepRunning = false
            app.shutdown()
            CFRunLoopStop(app.runLoop)
            exit(0)
        }
        sigtermSource.resume()
        
        app.installExtension()
        
        CFRunLoopRun()
        
        print("ProxyBridge stopped")
        exit(0)
    }
    
    func shutdown() {
        stopProxy()
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }
    
    func setupMessageReceiver(session: NETunnelProviderSession) {
        tunnelSession = session
        
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: session,
            queue: .main
        ) { [weak self] _ in
            self?.checkForLogs()
        }
        
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self = self, self.shouldKeepRunning else { return }
            self.checkForLogs()
        }
        
        print("Listening for connections...")
        print("")
        
        // Setup hardcoded proxy for testing
        setupTestProxyAndRule(session: session)
    }
    
    func setupTestProxyAndRule(session: NETunnelProviderSession) {
        // Set hardcoded SOCKS5 proxy
        let proxyConfig: [String: Any] = [
            "action": "setProxyConfig",
            "proxyType": "socks5",
            "proxyHost": "192.168.1.4",
            "proxyPort": 4444
        ]
        
        guard let configData = try? JSONSerialization.data(withJSONObject: proxyConfig) else { return }
        
        try? session.sendProviderMessage(configData) { response in
            print("✓ Proxy configured: socks5://192.168.1.4:4444")
            
            // After proxy is set, add test rule for curl
            let rule: [String: Any] = [
                "action": "addRule",
                "ruleId": 1,
                "processNames": "com.apple.curl",
                "targetHosts": "*",
                "targetPorts": "*",
                "ruleProtocol": "TCP",
                "ruleAction": "PROXY",
                "enabled": true
            ]
            
            guard let ruleData = try? JSONSerialization.data(withJSONObject: rule) else { return }
            
            try? session.sendProviderMessage(ruleData) { response in
                print("✓ Test rule added: com.apple.curl -> * -> * -> PROXY")
                print("")
            }
        }
    }
    
    func checkForLogs() {
        guard let session = tunnelSession else { return }
        
        let message = ["action": "getLogs"]
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
        
        try? session.sendProviderMessage(data) { response in
            guard let responseData = response,
                  let log = try? JSONSerialization.jsonObject(with: responseData) as? [String: String],
                  let type = log["type"], type == "connection",
                  let proto = log["protocol"],
                  let process = log["process"],
                  let dest = log["destination"],
                  let port = log["port"],
                  let proxy = log["proxy"] else {
                return
            }
            
            print("[\(proto)] \(process) -> \(dest):\(port) -> \(proxy)")
        }
    }
    
    func sendConfig(host: String, port: Int) {
        guard let session = tunnelSession else { return }
        
        var config: [String: Any] = [
            "action": "setProxyConfig",
            "host": host,
            "port": port
        ]
        
        // Add proxy config if available
        if let proxy = proxyConfig {
            config["proxyType"] = proxy.type
            config["proxyHost"] = proxy.host
            config["proxyPort"] = proxy.port
            if let username = proxy.username {
                config["proxyUsername"] = username
            }
            if let password = proxy.password {
                config["proxyPassword"] = password
            }
        }
        
        guard let data = try? JSONSerialization.data(withJSONObject: config) else { return }
        
        try? session.sendProviderMessage(data) { response in
            print("Config sent to extension")
        }
    }
    
    func parseArguments() {
        let args = CommandLine.arguments
        
        // Look for --proxy argument
        if let proxyIndex = args.firstIndex(of: "--proxy"),
           proxyIndex + 1 < args.count {
            let proxyUrl = args[proxyIndex + 1]
            
            if let config = parseProxyUrl(proxyUrl) {
                proxyConfig = config
                print("Proxy: \(config.type)://\(config.host):\(config.port)")
                if let username = config.username {
                    print("Proxy Auth: \(username):***")
                }
            } else {
                print("WARNING: Invalid proxy format: \(proxyUrl)")
                print("Use: type://ip:port or type://ip:port:username:password")
                print("Examples: socks5://127.0.0.1:1080")
                print("          http://proxy.com:8080:myuser:mypass")
            }
        }
    }
    
    func parseProxyUrl(_ proxyUrl: String) -> ProxyConfig? {
        var username: String? = nil
        var password: String? = nil
        
        if proxyUrl.starts(with: "socks5://") {
            let parts = String(proxyUrl.dropFirst(9)).split(separator: ":")
            if parts.count >= 2, let port = Int(parts[1]) {
                if parts.count >= 4 {
                    username = String(parts[2])
                    password = String(parts[3])
                }
                return ProxyConfig(
                    type: "socks5",
                    host: String(parts[0]),
                    port: port,
                    username: username,
                    password: password
                )
            }
        } else if proxyUrl.starts(with: "http://") {
            let parts = String(proxyUrl.dropFirst(7)).split(separator: ":")
            if parts.count >= 2, let port = Int(parts[1]) {
                if parts.count >= 4 {
                    username = String(parts[2])
                    password = String(parts[3])
                }
                return ProxyConfig(
                    type: "http",
                    host: String(parts[0]),
                    port: port,
                    username: username,
                    password: password
                )
            }
        }
        
        return nil
    }
    
    func stopProxy() {
        print("Stopping proxy")
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            guard let manager = managers?.first else { return }
            (manager.connection as? NETunnelProviderSession)?.stopTunnel()
        }
    }
    
    func installExtension() {
        print("Installing system extension")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "com.interceptsuite.ProxyBridge.extension",
            queue: .main
        )
        request.delegate = ExtensionDelegate.shared
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

class ExtensionDelegate: NSObject, OSSystemExtensionRequestDelegate {
    static let shared = ExtensionDelegate()
    
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("Replacing existing extension")
        return .replace
    }
    
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("ERROR: Extension needs user approval in System Settings")
        print("Go to: System Settings -> Privacy & Security -> Allow")
    }
    
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print("Extension installed successfully")
        startProxy()
    }
    
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("ERROR: Extension installation failed: \(error.localizedDescription)")
    }
    
    func startProxy() {
        print("Starting proxy tunnel")
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                print("ERROR: Failed to load managers: \(error.localizedDescription)")
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
                    print("ERROR: Failed to save preferences: \(saveError.localizedDescription)")
                    return
                }
                
                print("Configuration saved")
                
                manager.loadFromPreferences { loadError in
                    if let loadError = loadError {
                        print("ERROR: Failed to reload preferences: \(loadError.localizedDescription)")
                        return
                    }
                    
                    do {
                        try (manager.connection as? NETunnelProviderSession)?.startTunnel()
                        print("Proxy tunnel started")
                        
                        if let session = manager.connection as? NETunnelProviderSession {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                ProxyBridgeApp.shared.setupMessageReceiver(session: session)
                            }
                        }
                    } catch {
                        print("ERROR: Failed to start tunnel: \(error.localizedDescription)")
                    }
                }
            }
        }
    }
}

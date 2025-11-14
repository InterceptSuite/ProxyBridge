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
    
    static func main() {
        let app = ProxyBridgeApp.shared
        
        print("ProxyBridge CLI - Starting")
        
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
                  let port = log["port"] else {
                return
            }
            
            print("[\(proto)] \(process) -> \(dest):\(port)")
        }
    }
    
    func sendConfig(host: String, port: Int) {
        guard let session = tunnelSession else { return }
        
        let config = [
            "action": "setProxyConfig",
            "host": host,
            "port": port
        ] as [String : Any]
        
        guard let data = try? JSONSerialization.data(withJSONObject: config) else { return }
        
        try? session.sendProviderMessage(data) { response in
            print("Config sent to extension")
        }
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

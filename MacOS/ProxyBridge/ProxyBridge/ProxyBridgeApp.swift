//
//  ProxyBridgeApp.swift
//  ProxyBridge
//
//  Created by sourav kalal on 13/11/25.
//

import SwiftUI
import NetworkExtension
import SystemExtensions
import os.log

@main
struct ProxyBridgeApp: App {
    @Environment(\.scenePhase) private var scenePhase
    
    init() {
        os_log("App init - installing extension", type: .info)
        installExtension()
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .onChange(of: scenePhase) { oldPhase, newPhase in
            if newPhase == .background {
                os_log("App going to background, stopping proxy", type: .info)
                stopProxy()
            }
        }
    }
    
    func stopProxy() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            guard let manager = managers?.first else { return }
            (manager.connection as? NETunnelProviderSession)?.stopTunnel()
            os_log("Proxy tunnel stopped", type: .info)
        }
    }
    
    func installExtension() {
        os_log("Requesting extension installation", type: .info)
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
        os_log("Extension replacement requested", type: .info)
        return .replace
    }
    
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        os_log("Extension needs user approval in System Settings", type: .error)
    }
    
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        os_log("Extension installed successfully", type: .info)
        startProxy()
    }
    
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        os_log("Extension installation failed: %{public}@", type: .error, error.localizedDescription)
    }
    
    func startProxy() {
        os_log("Starting transparent proxy configuration", type: .info)
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                os_log("Failed to load managers: %{public}@", type: .error, error.localizedDescription)
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
                    os_log("Failed to save preferences: %{public}@", type: .error, saveError.localizedDescription)
                    return
                }
                
                os_log("Transparent proxy configuration saved", type: .info)
                
                manager.loadFromPreferences { loadError in
                    if let loadError = loadError {
                        os_log("Failed to reload preferences: %{public}@", type: .error, loadError.localizedDescription)
                        return
                    }
                    
                    do {
                        try (manager.connection as? NETunnelProviderSession)?.startTunnel()
                        os_log("Transparent proxy started", type: .info)
                    } catch {
                        os_log("Failed to start proxy: %{public}@", type: .error, error.localizedDescription)
                    }
                }
            }
        }
    }
}

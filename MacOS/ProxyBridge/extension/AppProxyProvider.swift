//
//  AppProxyProvider.swift
//  extension
//
//  Created by sourav kalal on 13/11/25.
//

import NetworkExtension
import os.log

class AppProxyProvider: NETransparentProxyProvider {
    
    private let logger = Logger(subsystem: "com.interceptsuite.ProxyBridge.extension", category: "NetworkProxy")
    private var logQueue: [[String: String]] = []
    private let queueLock = NSLock()

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
            queueLock.lock()
            if !logQueue.isEmpty {
                let log = logQueue.removeFirst()
                queueLock.unlock()
                completionHandler?(try? JSONSerialization.data(withJSONObject: log))
            } else {
                queueLock.unlock()
                completionHandler?(nil)
            }
        case "setProxyConfig":
            if let host = message["host"] as? String,
               let port = message["port"] as? Int {
                logger.info("Proxy config updated: \(host):\(port)")
            }
            let response = ["status": "ok"]
            completionHandler?(try? JSONSerialization.data(withJSONObject: response))
        case "setRules":
            if let rules = message["rules"] as? [[String: String]] {
                logger.info("Rules updated: \(rules.count) rules")
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
            logTCPConnection(tcpFlow)
        }
        // Let all traffic pass through directly
        return false
    }
    
    private func logTCPConnection(_ flow: NEAppProxyTCPFlow) {
        let remoteEndpoint = flow.remoteEndpoint
        var destination = ""
        var port = ""
        
        if let remoteHost = remoteEndpoint as? NWHostEndpoint {
            destination = remoteHost.hostname
            port = remoteHost.port
        } else {
            destination = String(describing: remoteEndpoint)
            port = "unknown"
        }
        
        var processName = "unknown"
        if let metaData = flow.metaData as? NEFlowMetaData {
            processName = metaData.sourceAppSigningIdentifier
        }
        
        sendLogToApp(protocol: "TCP", process: processName, destination: destination, port: port)
    }
    
    private func sendLogToApp(protocol: String, process: String, destination: String, port: String) {
        let logData: [String: String] = [
            "type": "connection",
            "protocol": `protocol`,
            "process": process,
            "destination": destination,
            "port": port,
            "proxy": "Direct"
        ]
        
        queueLock.lock()
        logQueue.append(logData)
        if logQueue.count > 1000 {
            logQueue.removeFirst()
        }
        queueLock.unlock()
    }
}



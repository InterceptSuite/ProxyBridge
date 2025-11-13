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

    override func startProxy(options: [String : Any]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Configuring transparent proxy")
        
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
            if let error = error {
                self.logger.error("Failed to set network settings: \(error.localizedDescription)")
                completionHandler(error)
            } else {
                self.logger.info("Transparent proxy started")
                completionHandler(nil)
            }
        }
    }
    
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Proxy stopped: \(reason.rawValue)")
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let handler = completionHandler {
            handler(messageData)
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
            handleTCP(tcpFlow)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            logUDPConnection(udpFlow)
            handleUDP(udpFlow)
        }
        return true
    }
    
    private func logTCPConnection(_ flow: NEAppProxyTCPFlow) {
        let remoteEndpoint = flow.remoteEndpoint
        
        if let remoteHost = remoteEndpoint as? NWHostEndpoint {
            logger.info("TCP -> \(remoteHost.hostname):\(remoteHost.port)")
        } else {
            logger.info("TCP -> \(String(describing: remoteEndpoint))")
        }
        
        if let metaData = flow.metaData as? NEFlowMetaData {
            logger.info("  App: \(metaData.sourceAppSigningIdentifier ?? "unknown")")
        }
    }
    
    private func logUDPConnection(_ flow: NEAppProxyUDPFlow) {
        if let localEndpoint = flow.localEndpoint,
           let localHost = localEndpoint as? NWHostEndpoint {
            logger.info("UDP: \(localHost.hostname):\(localHost.port)")
        }
        
        if let metaData = flow.metaData as? NEFlowMetaData {
            logger.info("  App: \(metaData.sourceAppSigningIdentifier ?? "unknown")")
        }
    }
    
    private func handleTCP(_ flow: NEAppProxyTCPFlow) {
        relayTCP(flow)
    }
    
    private func relayTCP(_ flow: NEAppProxyTCPFlow) {
        flow.readData { _, error in
            guard error == nil else { return }
            self.relayTCP(flow)
        }
    }
    
    private func handleUDP(_ flow: NEAppProxyUDPFlow) {
        relayUDP(flow)
    }
    
    private func relayUDP(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { _, _, error in
            guard error == nil else { return }
            self.relayUDP(flow)
        }
    }
}

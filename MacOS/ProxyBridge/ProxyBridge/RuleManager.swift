//
//  RuleManager.swift
//  ProxyBridge
//
//  Rule management helper for CLI
//

import Foundation
import NetworkExtension

struct RuleManager {
    
    // Send addRule command to extension
    static func addRule(
        session: NETunnelProviderSession,
        ruleId: UInt32,
        processNames: String,
        targetHosts: String,
        targetPorts: String,
        protocol: String,
        action: String,
        enabled: Bool = true,
        completion: @escaping (Bool, String) -> Void
    ) {
        let message: [String: Any] = [
            "action": "addRule",
            "ruleId": ruleId,
            "processNames": processNames,
            "targetHosts": targetHosts,
            "targetPorts": targetPorts,
            "ruleProtocol": `protocol`,
            "action": action,
            "enabled": enabled
        ]
        
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            completion(false, "Failed to serialize rule")
            return
        }
        
        try? session.sendProviderMessage(data) { response in
            guard let responseData = response,
                  let result = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
                  let status = result["status"] as? String else {
                completion(false, "No response from extension")
                return
            }
            
            if status == "ok" {
                completion(true, "Rule #\(ruleId) added successfully")
            } else if let message = result["message"] as? String {
                completion(false, "Error: \(message)")
            } else {
                completion(false, "Unknown error")
            }
        }
    }
    
    // Send removeRule command
    static func removeRule(
        session: NETunnelProviderSession,
        ruleId: UInt32,
        completion: @escaping (Bool, String) -> Void
    ) {
        let message: [String: Any] = [
            "action": "removeRule",
            "ruleId": ruleId
        ]
        
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            completion(false, "Failed to serialize message")
            return
        }
        
        try? session.sendProviderMessage(data) { response in
            guard let responseData = response,
                  let result = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
                  let status = result["status"] as? String else {
                completion(false, "No response from extension")
                return
            }
            
            if status == "ok" {
                let removed = result["removed"] as? Int ?? 0
                completion(true, "Removed \(removed) rule(s)")
            } else if let message = result["message"] as? String {
                completion(false, "Error: \(message)")
            } else {
                completion(false, "Unknown error")
            }
        }
    }
    
    // List all rules
    static func listRules(
        session: NETunnelProviderSession,
        completion: @escaping (Bool, [[String: Any]]) -> Void
    ) {
        let message: [String: Any] = [
            "action": "listRules"
        ]
        
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            completion(false, [])
            return
        }
        
        try? session.sendProviderMessage(data) { response in
            guard let responseData = response,
                  let result = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
                  let status = result["status"] as? String,
                  status == "ok",
                  let rules = result["rules"] as? [[String: Any]] else {
                completion(false, [])
                return
            }
            
            completion(true, rules)
        }
    }
    
    // Clear all rules
    static func clearRules(
        session: NETunnelProviderSession,
        completion: @escaping (Bool, String) -> Void
    ) {
        let message: [String: Any] = [
            "action": "clearRules"
        ]
        
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            completion(false, "Failed to serialize message")
            return
        }
        
        try? session.sendProviderMessage(data) { response in
            guard let responseData = response,
                  let result = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
                  let status = result["status"] as? String else {
                completion(false, "No response from extension")
                return
            }
            
            if status == "ok" {
                let cleared = result["cleared"] as? Int ?? 0
                completion(true, "Cleared \(cleared) rule(s)")
            } else if let message = result["message"] as? String {
                completion(false, "Error: \(message)")
            } else {
                completion(false, "Unknown error")
            }
        }
    }
    
    // Print rules in a nice format
    static func printRules(_ rules: [[String: Any]]) {
        if rules.isEmpty {
            print("No rules configured")
            return
        }
        
        print("\n=== Proxy Rules ===")
        print(String(format: "%-5s %-15s %-20s %-20s %-10s %-8s %-8s",
                     "ID", "Process", "Hosts", "Ports", "Protocol", "Action", "Enabled"))
        print(String(repeating: "-", count: 100))
        
        for rule in rules {
            let ruleId = rule["ruleId"] as? UInt32 ?? 0
            let processNames = (rule["processNames"] as? String ?? "*").prefix(15)
            let targetHosts = (rule["targetHosts"] as? String ?? "*").prefix(20)
            let targetPorts = (rule["targetPorts"] as? String ?? "*").prefix(20)
            let proto = rule["protocol"] as? String ?? "BOTH"
            let action = rule["action"] as? String ?? "DIRECT"
            let enabled = rule["enabled"] as? Bool ?? true
            
            print(String(format: "%-5d %-15s %-20s %-20s %-10s %-8s %-8s",
                         ruleId,
                         String(processNames),
                         String(targetHosts),
                         String(targetPorts),
                         proto,
                         action,
                         enabled ? "Yes" : "No"))
        }
        print("")
    }
}

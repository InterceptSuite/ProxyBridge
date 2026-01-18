import Foundation
import NetworkExtension

struct RuleManager {
    
    static func addRule(
        session: NETunnelProviderSession,
        processNames: String,
        targetHosts: String,
        targetPorts: String,
        protocol: String,
        action: String,
        enabled: Bool = true,
        completion: @escaping (Bool, String, UInt32?) -> Void
    ) {
        sendMessage(
            session: session,
            action: "addRule",
            params: [
                "processNames": processNames,
                "targetHosts": targetHosts,
                "targetPorts": targetPorts,
                "ruleProtocol": `protocol`,
                "ruleAction": action,
                "enabled": enabled
            ]
        ) { success, result in
            if success, let result = result, let ruleId = result["ruleId"] as? UInt32 {
                completion(true, "Rule added successfully", ruleId)
            } else {
                completion(false, result?["message"] as? String ?? "Unknown error", nil)
            }
        }
    }
    
    static func updateRule(
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
        sendMessage(
            session: session,
            action: "updateRule",
            params: [
                "ruleId": ruleId,
                "processNames": processNames,
                "targetHosts": targetHosts,
                "targetPorts": targetPorts,
                "ruleProtocol": `protocol`,
                "ruleAction": action,
                "enabled": enabled
            ]
        ) { success, result in
            let message = success
                ? "Rule #\(ruleId) updated successfully"
                : (result?["message"] as? String ?? "Unknown error")
            completion(success, message)
        }
    }
    
    static func toggleRule(
        session: NETunnelProviderSession,
        ruleId: UInt32,
        enabled: Bool,
        completion: @escaping (Bool, String) -> Void
    ) {
        sendMessage(
            session: session,
            action: "toggleRule",
            params: ["ruleId": ruleId, "enabled": enabled]
        ) { success, result in
            let message = success
                ? "Rule #\(ruleId) \(enabled ? "enabled" : "disabled")"
                : (result?["message"] as? String ?? "Unknown error")
            completion(success, message)
        }
    }
    
    static func removeRule(
        session: NETunnelProviderSession,
        ruleId: UInt32,
        completion: @escaping (Bool, String) -> Void
    ) {
        sendMessage(
            session: session,
            action: "removeRule",
            params: ["ruleId": ruleId]
        ) { success, result in
            let message = success
                ? "Removed \(result?["removed"] as? Int ?? 0) rule(s)"
                : (result?["message"] as? String ?? "Unknown error")
            completion(success, message)
        }
    }
    
    static func listRules(
        session: NETunnelProviderSession,
        completion: @escaping (Bool, [[String: Any]]) -> Void
    ) {
        sendMessage(session: session, action: "listRules", params: [:]) { success, result in
            if success, let rules = result?["rules"] as? [[String: Any]] {
                completion(true, rules)
            } else {
                completion(false, [])
            }
        }
    }
    
    static func clearRules(
        session: NETunnelProviderSession,
        completion: @escaping (Bool, String) -> Void
    ) {
        sendMessage(session: session, action: "clearRules", params: [:]) { success, result in
            let message = success
                ? "Cleared \(result?["cleared"] as? Int ?? 0) rule(s)"
                : (result?["message"] as? String ?? "Unknown error")
            completion(success, message)
        }
    }
    
    private static func sendMessage(
        session: NETunnelProviderSession,
        action: String,
        params: [String: Any],
        completion: @escaping (Bool, [String: Any]?) -> Void
    ) {
        var message = params
        message["action"] = action
        
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            completion(false, nil)
            return
        }
        
        try? session.sendProviderMessage(data) { response in
            guard let responseData = response,
                  let result = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
                  let status = result["status"] as? String else {
                completion(false, nil)
                return
            }
            
            completion(status == "ok", result)
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
    
    static func saveRulesToUserDefaults(_ rules: [[String: Any]]) {
        let rulesToSave = rules.map { rule -> [String: Any] in
            var ruleData = rule
            ruleData.removeValue(forKey: "ruleId")
            return ruleData
        }
        UserDefaults.standard.set(rulesToSave, forKey: "proxyRules")
    }
    
    static func loadRulesFromUserDefaults(
        session: NETunnelProviderSession,
        completion: @escaping (Bool, Int) -> Void
    ) {
        let rules = UserDefaults.standard.array(forKey: "proxyRules") as? [[String: Any]] ?? []
        
        guard !rules.isEmpty else {
            completion(true, 0)
            return
        }
        
        // First, get existing rules to avoid duplicates
        listRules(session: session) { success, existingRules in
            guard success else {
                completion(false, 0)
                return
            }
            
            var successCount = 0
            let group = DispatchGroup()
            
            for rule in rules {
                // Check if a rule with the same properties already exists
                let ruleExists = existingRules.contains { existing in
                    existing["processNames"] as? String == rule["processNames"] as? String &&
                    existing["targetHosts"] as? String == rule["targetHosts"] as? String &&
                    existing["targetPorts"] as? String == rule["targetPorts"] as? String &&
                    existing["protocol"] as? String == rule["protocol"] as? String &&
                    existing["action"] as? String == rule["action"] as? String &&
                    existing["enabled"] as? Bool == rule["enabled"] as? Bool
                }
                
                // Only add if the rule doesn't already exist
                if !ruleExists {
                    group.enter()
                    addRule(
                        session: session,
                        processNames: rule["processNames"] as? String ?? "",
                        targetHosts: rule["targetHosts"] as? String ?? "",
                        targetPorts: rule["targetPorts"] as? String ?? "",
                        protocol: rule["protocol"] as? String ?? "BOTH",
                        action: rule["action"] as? String ?? "DIRECT",
                        enabled: rule["enabled"] as? Bool ?? true
                    ) { success, _, _ in
                        if success { successCount += 1 }
                        group.leave()
                    }
                }
            }
            
            group.notify(queue: .main) {
                completion(true, successCount)
            }
        }
    }
}

import Foundation
import NetworkExtension
import SystemExtensions
import Combine
import AppKit

class ProxyBridgeViewModel: NSObject, ObservableObject {
    @Published var connections: [ConnectionLog] = []
    @Published var activityLogs: [ActivityLog] = []
    @Published var isProxyActive = false
    @Published var isTrafficLoggingEnabled = true
    
    var tunnelSession: NETunnelProviderSession?
    private var logTimer: Timer?
    @Published private(set) var proxyConfigs: [ProxyConfig] = []
    @Published private(set) var profiles: [String] = []
    @Published private(set) var activeProfile: String = "Default"
    
    private let maxLogEntries = 500
    // trim back to this when the cap is hit, so we don't shift on every entry
    private let trimToEntries = 400
    private let logPollingInterval = 1.0
    private let extensionIdentifier = "com.interceptsuite.ProxyBridge.extension"
    private let timestampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
    private var connectionIdCounter: Int = 0
    private var activityIdCounter: Int = 0
    
    struct ProxyConfig: Identifiable, Codable {
        let id: String
        var name: String
        let type: String
        let host: String
        let port: Int
        let username: String?
        let password: String?
        // same as the windows app: true = the proxy gets the host name the app resolved
        // (socks5h / CONNECT host:port), false = it gets the ip. per proxy, on by default
        var sendDomain: Bool

        // name is optional, show type and host:port either way
        var displayName: String {
            let server = "\(type.uppercased()) \(host):\(port)"
            return name.isEmpty ? server : "\(name) = \(server)"
        }

        init(id: String = UUID().uuidString, name: String = "", type: String, host: String, port: Int, username: String?, password: String?, sendDomain: Bool = true) {
            self.sendDomain = sendDomain
            self.id = id
            self.name = name
            self.type = type
            self.host = host
            self.port = port
            self.username = username
            self.password = password
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.id = try c.decode(String.self, forKey: .id)
            self.name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
            self.type = try c.decode(String.self, forKey: .type)
            self.host = try c.decode(String.self, forKey: .host)
            self.port = try c.decode(Int.self, forKey: .port)
            self.username = try c.decodeIfPresent(String.self, forKey: .username)
            self.password = try c.decodeIfPresent(String.self, forKey: .password)
            // proxies saved before this option existed behave like the windows default
            self.sendDomain = try c.decodeIfPresent(Bool.self, forKey: .sendDomain) ?? true
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
    
    // when every window is hidden or minimized there's no point polling logs
    private var isWindowVisible = true

    override init() {
        super.init()
        // both arrays are capped at maxLogEntries, reserve up front so a busy
        // session doesn't keep reallocating the backing storage as it fills
        connections.reserveCapacity(maxLogEntries)
        activityLogs.reserveCapacity(maxLogEntries)
        loadTrafficLoggingSetting()
        loadProfiles()
        loadProxyConfig()
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(occlusionChanged),
            name: NSApplication.didChangeOcclusionStateNotification,
            object: nil
        )
        installAndStartProxy()
    }

    @objc private func occlusionChanged() {
        isWindowVisible = NSApp.occlusionState.contains(.visible)
        updatePollingState()
    }

    // single place that decides whether the poll timer should be running
    private func updatePollingState() {
        if isTrafficLoggingEnabled && tunnelSession != nil && isWindowVisible {
            startLogPollingTimer()
        } else {
            stopLogPollingTimer()
        }
    }

    private func stopLogPollingTimer() {
        DispatchQueue.main.async { [weak self] in
            self?.logTimer?.invalidate()
            self?.logTimer = nil
        }
    }
    
    private func loadTrafficLoggingSetting() {
        isTrafficLoggingEnabled = UserDefaults.standard.object(forKey: "trafficLoggingEnabled") as? Bool ?? true
    }
    
    func toggleTrafficLogging() {
        isTrafficLoggingEnabled.toggle()
        UserDefaults.standard.set(isTrafficLoggingEnabled, forKey: "trafficLoggingEnabled")
        sendTrafficLoggingToExtension(isTrafficLoggingEnabled)
        updatePollingState()
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
        } else {
            proxyConfigs = []
        }
    }

    // MARK: - Profiles
    //
    // a profile bundles the proxy configs + rules. the live "proxyConfigs" and
    // "proxyRules" UserDefaults keys always hold the active profile so the rest
    // of the app and the extension keep reading them unchanged. switching just
    // snapshots the current profile and swaps in another one's data.

    private func profileConfigsKey(_ name: String) -> String { "profile.\(name).proxyConfigs" }
    private func profileRulesKey(_ name: String) -> String { "profile.\(name).proxyRules" }
    private func profileLoggingKey(_ name: String) -> String { "profile.\(name).trafficLoggingEnabled" }
    private func profileCloseKey(_ name: String) -> String { "profile.\(name).closeToMenuBar" }
    private func profileStartupKey(_ name: String) -> String { "profile.\(name).runAtStartup" }

    private func loadProfiles() {
        let d = UserDefaults.standard
        var names = d.stringArray(forKey: "profiles") ?? []
        if names.isEmpty {
            // first run, seed a Default profile from whatever is already stored
            names = ["Default"]
            d.set(names, forKey: "profiles")
            d.set("Default", forKey: "activeProfile")
            flushWorkingSet(to: "Default")
        }
        profiles = names
        activeProfile = d.string(forKey: "activeProfile") ?? names.first ?? "Default"
    }

    // copy the live working keys into a profile's snapshot
    private func flushWorkingSet(to name: String) {
        let d = UserDefaults.standard
        d.set(d.data(forKey: "proxyConfigs"), forKey: profileConfigsKey(name))
        d.set(d.array(forKey: "proxyRules"), forKey: profileRulesKey(name))
        d.set(isTrafficLoggingEnabled, forKey: profileLoggingKey(name))
        d.set(d.bool(forKey: "closeToMenuBar"), forKey: profileCloseKey(name))
        d.set(d.bool(forKey: "runAtStartup"), forKey: profileStartupKey(name))
    }

    // load a profile's snapshot into the live working keys
    private func loadWorkingSet(from name: String) {
        let d = UserDefaults.standard
        if let data = d.data(forKey: profileConfigsKey(name)) {
            d.set(data, forKey: "proxyConfigs")
        } else {
            d.removeObject(forKey: "proxyConfigs")
        }
        d.set(d.array(forKey: profileRulesKey(name)) ?? [], forKey: "proxyRules")
        // traffic logging is per profile, default on when the snapshot has none
        d.set(d.object(forKey: profileLoggingKey(name)) as? Bool ?? true, forKey: "trafficLoggingEnabled")
        // window + startup behaviour are per profile too, default off
        d.set(d.object(forKey: profileCloseKey(name)) as? Bool ?? false, forKey: "closeToMenuBar")
        d.set(d.object(forKey: profileStartupKey(name)) as? Bool ?? false, forKey: "runAtStartup")
    }

    // reload in-memory state from the working keys and push it to the extension
    private func applyActiveProfile() {
        loadProxyConfig()
        loadTrafficLoggingSetting()
        // window-close behaviour is read live from the key, only startup needs applying
        LoginItem.applyToSystem(UserDefaults.standard.bool(forKey: "runAtStartup"))
        if let session = tunnelSession {
            sendProxyConfigsToExtension(session: session)
            RuleManager.resyncRules(session: session) { _, _ in }
            sendTrafficLoggingToExtension(isTrafficLoggingEnabled)
        }
        updatePollingState()
    }

    func switchProfile(to name: String) {
        guard name != activeProfile, profiles.contains(name) else { return }
        flushWorkingSet(to: activeProfile)
        loadWorkingSet(from: name)
        activeProfile = name
        UserDefaults.standard.set(name, forKey: "activeProfile")
        applyActiveProfile()
    }

    func createProfile(_ rawName: String) {
        let name = rawName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !profiles.contains(name) else { return }
        // new profiles start empty
        UserDefaults.standard.removeObject(forKey: profileConfigsKey(name))
        UserDefaults.standard.set([[String: Any]](), forKey: profileRulesKey(name))
        profiles.append(name)
        UserDefaults.standard.set(profiles, forKey: "profiles")
        switchProfile(to: name)
    }

    func renameProfile(_ old: String, to rawNew: String) {
        let new = rawNew.trimmingCharacters(in: .whitespaces)
        guard !new.isEmpty, profiles.contains(old), !profiles.contains(new) else { return }
        let d = UserDefaults.standard
        // make sure the active profile's snapshot is current before moving it
        if old == activeProfile { flushWorkingSet(to: old) }
        d.set(d.data(forKey: profileConfigsKey(old)), forKey: profileConfigsKey(new))
        d.set(d.array(forKey: profileRulesKey(old)), forKey: profileRulesKey(new))
        d.set(d.object(forKey: profileLoggingKey(old)), forKey: profileLoggingKey(new))
        d.set(d.object(forKey: profileCloseKey(old)), forKey: profileCloseKey(new))
        d.set(d.object(forKey: profileStartupKey(old)), forKey: profileStartupKey(new))
        d.removeObject(forKey: profileConfigsKey(old))
        d.removeObject(forKey: profileRulesKey(old))
        d.removeObject(forKey: profileLoggingKey(old))
        d.removeObject(forKey: profileCloseKey(old))
        d.removeObject(forKey: profileStartupKey(old))
        if let i = profiles.firstIndex(of: old) { profiles[i] = new }
        d.set(profiles, forKey: "profiles")
        if activeProfile == old {
            activeProfile = new
            d.set(new, forKey: "activeProfile")
        }
    }

    func deleteProfile(_ name: String) {
        guard profiles.count > 1, profiles.contains(name) else { return }
        // can't delete the one we're on, move to another first
        if name == activeProfile, let other = profiles.first(where: { $0 != name }) {
            switchProfile(to: other)
        }
        let d = UserDefaults.standard
        d.removeObject(forKey: profileConfigsKey(name))
        d.removeObject(forKey: profileRulesKey(name))
        d.removeObject(forKey: profileLoggingKey(name))
        d.removeObject(forKey: profileCloseKey(name))
        d.removeObject(forKey: profileStartupKey(name))
        profiles.removeAll { $0 == name }
        d.set(profiles, forKey: "profiles")
    }

    // build a portable .pbprofile json for a profile
    func exportProfileData(_ name: String) -> Data? {
        guard profiles.contains(name) else { return nil }
        // make sure the active profile's snapshot reflects the latest edits
        if name == activeProfile { flushWorkingSet(to: name) }
        let d = UserDefaults.standard
        let configsJSON = d.data(forKey: profileConfigsKey(name))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) } ?? []
        let dict: [String: Any] = [
            "name": name,
            "trafficLoggingEnabled": d.object(forKey: profileLoggingKey(name)) as? Bool ?? true,
            "closeToMenuBar": d.object(forKey: profileCloseKey(name)) as? Bool ?? false,
            "runAtStartup": d.object(forKey: profileStartupKey(name)) as? Bool ?? false,
            "proxyConfigs": configsJSON,
            "proxyRules": d.array(forKey: profileRulesKey(name)) ?? []
        ]
        return try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys])
    }

    // create a new profile from a .pbprofile json and switch to it
    @discardableResult
    func importProfile(from data: Data) -> Bool {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        var base = (obj["name"] as? String)?.trimmingCharacters(in: .whitespaces) ?? "Imported"
        if base.isEmpty { base = "Imported" }
        let name = uniqueProfileName(base)

        let d = UserDefaults.standard
        // re-encode the configs array back to the Data form we store, ids are kept
        // so each rule's action still points at the right proxy config
        if let configsJSON = obj["proxyConfigs"],
           let configsData = try? JSONSerialization.data(withJSONObject: configsJSON) {
            d.set(configsData, forKey: profileConfigsKey(name))
        } else {
            d.removeObject(forKey: profileConfigsKey(name))
        }
        d.set(obj["proxyRules"] as? [[String: Any]] ?? [], forKey: profileRulesKey(name))
        d.set(obj["trafficLoggingEnabled"] as? Bool ?? true, forKey: profileLoggingKey(name))
        d.set(obj["closeToMenuBar"] as? Bool ?? false, forKey: profileCloseKey(name))
        d.set(obj["runAtStartup"] as? Bool ?? false, forKey: profileStartupKey(name))

        profiles.append(name)
        d.set(profiles, forKey: "profiles")
        switchProfile(to: name)
        return true
    }

    private func uniqueProfileName(_ base: String) -> String {
        if !profiles.contains(base) { return base }
        var i = 2
        while profiles.contains("\(base) (\(i))") { i += 1 }
        return "\(base) (\(i))"
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
                    RuleManager.resyncRules(session: session) { _, _ in }
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

    // enables the dns proxy provider so the extension can see dns resolutions and
    // build the ip -> domain map used for domain rules
    func startDNSProxy() {
        let manager = NEDNSProxyManager.shared()
        manager.loadFromPreferences { [weak self] _ in
            guard let self = self else { return }
            let proto = NEDNSProxyProviderProtocol()
            proto.providerBundleIdentifier = self.extensionIdentifier
            manager.providerProtocol = proto
            manager.localizedDescription = "ProxyBridge DNS"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error = error {
                    self.addLog("ERROR", "DNS proxy setup failed: \(error.localizedDescription)")
                } else {
                    self.addLog("INFO", "DNS proxy enabled")
                }
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
        // clearing rules fixes #51 where rules stayed active after the app closed
        RuleManager.clearRules(session: session) { success, message in
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
        updatePollingState()
    }
    
    private func startLogPollingTimer() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            // already running, don't reset the cadence
            guard self.logTimer == nil else { return }
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
                  let logs = try? JSONSerialization.jsonObject(with: responseData) as? [[String: String]],
                  !logs.isEmpty else {
                return
            }

            // build the batch first, then touch the published arrays once each
            // so a busy second is one ui update instead of a hundred
            DispatchQueue.main.async {
                var newConnections: [ConnectionLog] = []
                var newActivity: [ActivityLog] = []
                for log in logs {
                    if log["type"] == "connection" {
                        if let c = self.makeConnectionLog(log) { newConnections.append(c) }
                    } else {
                        if let a = self.makeActivityLog(log) { newActivity.append(a) }
                    }
                }
                self.appendConnections(newConnections)
                self.appendActivity(newActivity)
            }
        }
    }

    private func appendConnections(_ items: [ConnectionLog]) {
        guard !items.isEmpty else { return }
        connections.append(contentsOf: items)
        if connections.count > maxLogEntries {
            connections.removeFirst(connections.count - trimToEntries)
        }
    }

    private func appendActivity(_ items: [ActivityLog]) {
        guard !items.isEmpty else { return }
        activityLogs.append(contentsOf: items)
        if activityLogs.count > maxLogEntries {
            activityLogs.removeFirst(activityLogs.count - trimToEntries)
        }
    }

    private func makeConnectionLog(_ log: [String: String]) -> ConnectionLog? {
        guard isTrafficLoggingEnabled else { return nil }

        guard let proto = log["protocol"],
              let process = log["process"],
              let dest = log["destination"],
              let port = log["port"],
              let proxy = log["proxy"] else {
            return nil
        }

        connectionIdCounter &+= 1
        return ConnectionLog(
            id: connectionIdCounter,
            timestamp: getCurrentTimestamp(),
            connectionProtocol: proto,
            process: process,
            destination: dest,
            port: port,
            proxy: proxy
        )
    }

    private func makeActivityLog(_ log: [String: String]) -> ActivityLog? {
        guard let timestamp = log["timestamp"],
              let level = log["level"],
              let message = log["message"] else {
            return nil
        }

        activityIdCounter &+= 1
        return ActivityLog(
            id: activityIdCounter,
            timestamp: timestamp,
            level: level,
            message: message
        )
    }

    func sendProxyConfigsToExtension(session: NETunnelProviderSession) {
        let configsArray: [[String: Any]] = proxyConfigs.map { config in
            var dict: [String: Any] = [
                "id": config.id,
                "proxyType": config.type,
                "proxyHost": config.host,
                "proxyPort": config.port,
                "sendDomainToProxy": config.sendDomain
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
        appendActivity([log])
    }
    
    private func getCurrentTimestamp() -> String {
        return timestampFormatter.string(from: Date())
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
        logTimer?.invalidate()
        stopProxy()
    }
}

extension ProxyBridgeViewModel: OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        DispatchQueue.main.async {
            self.addLog("INFO", "Extension installed successfully")
            self.startProxy()
            self.startDNSProxy()
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

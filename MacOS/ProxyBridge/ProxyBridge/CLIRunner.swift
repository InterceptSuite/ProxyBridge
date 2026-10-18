import Foundation
import AppKit
import NetworkExtension
import SystemExtensions

// the command line mode of the app: the same executable as the GUI, started with options
// (see main.swift). it does what the GUI does to get traffic redirected, without a window:
// activate the system extension, set up the tunnel, send the profile, and clean up on exit.
enum CLI {
    static let bundleIdentifier = "com.interceptsuite.ProxyBridge"
    static let extensionIdentifier = "com.interceptsuite.ProxyBridge.extension"
    static let maxProfileBytes = 4 * 1024 * 1024
    static var runner: CLIRunner?
    private static var lockDescriptor: Int32 = -1
    private static var outputClosed = false

    // prints a line. when the reader of our output went away (piped into `head`, closed
    // terminal) we stop cleanly instead of dying on SIGPIPE with the rules still active
    static func say(_ text: String) {
        guard !outputClosed else { return }
        if fputs(text + "\n", stdout) == EOF || fflush(stdout) != 0 {
            outputClosed = true
            runner?.stopFromOutside(reason: nil)
        }
    }

    static func warn(_ text: String) {
        FileHandle.standardError.write(Data(("warning: " + text + "\n").utf8))
    }

    static func fail(_ text: String, code: Int32 = 1) -> Never {
        FileHandle.standardError.write(Data(("ERROR: " + CLIText.lines(text) + "\n").utf8))
        exit(code)
    }

    // the version of the app this executable belongs to. falls back to the bundle that
    // holds the real executable in case the process was started through a link
    static func version() -> String {
        if let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String { return v }
        if let exe = Bundle.main.executableURL?.resolvingSymlinksInPath() {
            let plist = exe.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Info.plist")
            if let d = NSDictionary(contentsOf: plist), let v = d["CFBundleShortVersionString"] as? String { return v }
        }
        return "unknown"
    }

    static func run(arguments: [String]) -> Never {
        // a closed pipe must not kill us: we want to clean up first (see say)
        signal(SIGPIPE, SIG_IGN)

        let options: CLIOptions
        switch CLIArguments.parse(arguments) {
        case .failure(let message): fail(message, code: 2)
        case .run(let o): options = o
        }

        if options.help { say(CLIArguments.usage); exit(0) }
        if options.version { say("ProxyBridge CLI \(version())"); exit(0) }
        if options.listProfiles { listProfiles(); exit(0) }
        if options.update { checkForUpdates() }

        guard let spec = options.profile else { fail("--profile is required. Use --help.", code: 2) }
        let profile: CLIProfile
        do { profile = try loadProfile(spec) } catch let e as CLIProfileError { fail(e.message) } catch { fail(error.localizedDescription) }

        let errors = CLIProfileLoader.errors(for: profile)
        if !errors.isEmpty { fail("The profile can't be used:\n  - " + errors.map { CLIText.safe($0) }.joined(separator: "\n  - ")) }

        // only one controller at a time: the GUI and the CLI would fight over the same tunnel
        if guiIsRunning() { fail("The ProxyBridge app is running. Quit it first, only one of them can control the extension at a time.") }
        guard takeLock() else { fail("Another ProxyBridge CLI is already running.") }

        for w in CLIProfileLoader.warnings(for: profile) { warn(CLIText.safe(w)) }
        let r = CLIRunner(profile: profile, verbose: options.verbose)
        runner = r
        r.start()
        RunLoop.main.run()
        exit(0)
    }

    private static func listProfiles() {
        let (names, active) = CLIProfileLoader.savedNames(read: CLIProfileLoader.appReader)
        if names.isEmpty { say("No saved profiles. Open the ProxyBridge app once to create the default one."); return }
        for n in names { say((n == active ? "* " : "  ") + CLIText.safe(n)) }
        say("(* = the profile the app currently uses)")
    }

    // standard input, with a limit so a huge or endless input can't use all the memory
    private static func readStandardInput() throws -> Data {
        if isatty(STDIN_FILENO) != 0 {
            throw CLIProfileError.invalid("--profile - reads the profile from standard input, but standard input is the terminal. Pipe a file in: cat file.pbprofile | proxybridge --profile -")
        }
        var data = Data()
        while true {
            let chunk = FileHandle.standardInput.availableData
            if chunk.isEmpty { return data }
            data.append(chunk)
            if data.count > maxProfileBytes { throw CLIProfileError.invalid("The profile is larger than \(maxProfileBytes / 1024 / 1024) MB.") }
        }
    }

    private static func loadProfile(_ spec: String) throws -> CLIProfile {
        if spec == "-" { return try CLIProfileLoader.parse(json: readStandardInput()) }
        if spec.contains("/") || spec.hasSuffix(".pbprofile") {
            // the app is sandboxed, so it can only read files that are in its own container
            let path = (spec as NSString).expandingTildeInPath
            guard let data = FileManager.default.contents(atPath: path), data.count <= maxProfileBytes else {
                throw CLIProfileError.invalid("Can't read '\(spec)'. The app is sandboxed and can't open files elsewhere. Use a saved profile name, or pipe the file in: cat \(spec) | proxybridge --profile -")
            }
            return try CLIProfileLoader.parse(json: data)
        }
        return try CLIProfileLoader.saved(named: spec, read: CLIProfileLoader.appReader)
    }

    private static func checkForUpdates() -> Never {
        Task {
            let info = await UpdateService().checkForUpdates()
            if let error = info.error { fail(error) }
            say("Installed: \(info.currentVersion)")
            say("Latest:    \(info.latestVersion)")
            if info.isUpdateAvailable {
                say("An update is available: \(CLIText.safe(info.downloadUrl ?? "see https://github.com/InterceptSuite/ProxyBridge/releases"))")
                if let notes = info.releaseNotesUrl { say("Release notes: \(CLIText.safe(notes))") }
            } else {
                say("You are up to date.")
            }
            exit(0)
        }
        RunLoop.main.run()
        exit(0)
    }

    private static func guiIsRunning() -> Bool {
        NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier).contains { $0.processIdentifier != getpid() }
    }

    // a second CLI would clear the first one's rules when it stops
    private static func takeLock() -> Bool {
        let path = NSTemporaryDirectory() + "proxybridge-cli.lock"
        lockDescriptor = open(path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        return lockDescriptor >= 0 && flock(lockDescriptor, LOCK_EX | LOCK_NB) == 0
    }
}

final class CLIRunner: NSObject, OSSystemExtensionRequestDelegate {
    private let profile: CLIProfile
    private let verbose: Int
    private var manager: NETransparentProxyManager?
    private var session: NETunnelProviderSession?
    private var statusObserver: NSObjectProtocol?
    private var logTimer: Timer?
    private var polling = false
    private var signalSources: [DispatchSourceSignal] = []
    private var extensionActive = false
    private var started = false
    private var stopping = false
    private let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    init(profile: CLIProfile, verbose: Int) {
        self.profile = profile
        self.verbose = verbose
        super.init()
    }

    func start() {
        installSignalHandlers()
        CLI.say("ProxyBridge CLI \(CLI.version())")
        CLI.say("Extension: activating...")
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: CLI.extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        // the first run can wait for a person to approve the extension, but not forever
        DispatchQueue.main.asyncAfter(deadline: .now() + 300) { [weak self] in
            if let self = self, !self.extensionActive { self.fail("Timed out waiting for the extension. Approve it in System Settings > Privacy & Security and run the command again.") }
        }
    }

    // MARK: - extension

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        DispatchQueue.main.async {
            // an update that macOS finishes after a restart is not running yet
            if result == .willCompleteAfterReboot {
                self.fail("macOS will finish activating the system extension after a restart. Restart your Mac and run the command again.")
                return
            }
            self.extensionActive = true
            CLI.say("Extension: active")
            self.configureTunnel()
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        DispatchQueue.main.async { self.fail("The system extension could not be activated: \(error.localizedDescription)") }
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        CLI.say("Extension: waiting for your approval. Open System Settings > Privacy & Security and click Allow, then enter your password. This is needed once.")
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    // MARK: - tunnel

    private func configureTunnel() {
        CLI.say("Network configuration: setting up (macOS asks you to allow it the first time)...")
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if let error = error { self.fail("Could not load the network configuration: \(error.localizedDescription)"); return }
                let manager = managers?.first ?? NETransparentProxyManager()
                manager.localizedDescription = "ProxyBridge Transparent Proxy"
                manager.isEnabled = true
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = CLI.extensionIdentifier
                proto.serverAddress = "ProxyBridge"
                manager.protocolConfiguration = proto
                manager.saveToPreferences { saveError in
                    DispatchQueue.main.async {
                        if let saveError = saveError { self.fail("Could not save the network configuration: \(saveError.localizedDescription)"); return }
                        manager.loadFromPreferences { loadError in
                            DispatchQueue.main.async {
                                if let loadError = loadError { self.fail("Could not reload the network configuration: \(loadError.localizedDescription)"); return }
                                self.startTunnel(manager)
                            }
                        }
                    }
                }
            }
        }
    }

    private func startTunnel(_ manager: NETransparentProxyManager) {
        self.manager = manager
        guard let session = manager.connection as? NETunnelProviderSession else { fail("The tunnel session is not available."); return }
        self.session = session

        // watch the tunnel for as long as we run: it connects once, and if something else stops it
        // later (the app being opened, the extension crashing) nothing is redirected any more and
        // the user has to be told instead of being left with a CLI that looks fine
        statusObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: session, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            switch session.status {
            case .connected:
                if !self.started { self.applyProfile() }
            case .disconnected, .invalid:
                if self.started && !self.stopping {
                    self.fail("The tunnel was stopped by something else (is the ProxyBridge app running?). Nothing is being redirected any more.")
                }
            default: break
            }
        }

        if session.status == .connected { applyProfile(); return }
        do { try session.startTunnel() } catch { fail("Could not start the tunnel: \(error.localizedDescription)"); return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            if let self = self, !self.started { self.fail("The tunnel did not start in 30 seconds.") }
        }
    }

    // MARK: - profile

    private func applyProfile() {
        guard !started, !stopping, let session = session else { return }
        started = true
        enableDNSProxy()

        // same messages, same order as the GUI: logging, proxies, then the rules in one step
        send(["action": "setTrafficLogging", "enabled": verbose >= 2]) { _ in
            self.send(["action": "setProxyConfigs", "configs": self.proxyMessages()]) { _ in
                RuleManager.applyRules(session: session, rules: self.profile.rules) { _, count in
                    CLI.say("Profile \"\(CLIText.safe(self.profile.name))\": \(self.profile.proxies.count) proxies, \(count) rules applied")
                    // the extension skips a rule it can't read, don't let that pass silently
                    if count < self.profile.rules.count { CLI.warn("\(self.profile.rules.count - count) rule(s) were rejected by the extension (invalid fields)") }
                    CLI.say("Redirecting traffic. Press Ctrl+C to stop.")
                    if self.verbose > 0 { self.startLogPolling() }
                }
            }
        }
    }

    private func proxyMessages() -> [[String: Any]] {
        profile.proxies.map { p in
            var dict: [String: Any] = ["id": p.id, "proxyType": p.type, "proxyHost": p.host, "proxyPort": p.port, "sendDomainToProxy": p.sendDomain]
            if let u = p.username { dict["proxyUsername"] = u }
            if let pw = p.password { dict["proxyPassword"] = pw }
            return dict
        }
    }

    // the DNS provider is what makes domain rules and hostnames work, the GUI turns it on too.
    // when it is already set up for this extension it is left alone, saving it again on every
    // start is a needless system configuration change
    private func enableDNSProxy() {
        let dns = NEDNSProxyManager.shared()
        dns.loadFromPreferences { loadError in
            if loadError == nil, dns.isEnabled, dns.providerProtocol?.providerBundleIdentifier == CLI.extensionIdentifier { return }
            let proto = NEDNSProxyProviderProtocol()
            proto.providerBundleIdentifier = CLI.extensionIdentifier
            dns.providerProtocol = proto
            dns.localizedDescription = "ProxyBridge DNS"
            dns.isEnabled = true
            dns.saveToPreferences { error in
                if let error = error { CLI.warn("DNS proxy setup failed: \(error.localizedDescription)") }
            }
        }
    }

    private func send(_ message: [String: Any], completion: (([String: Any]?) -> Void)? = nil) {
        guard let session = session, let data = try? JSONSerialization.data(withJSONObject: message) else { completion?(nil); return }
        do {
            try session.sendProviderMessage(data) { response in
                let object = response.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
                DispatchQueue.main.async { completion?(object) }
            }
        } catch {
            DispatchQueue.main.async { completion?(nil) }
        }
    }

    // MARK: - logs

    private func startLogPolling() {
        logTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in self?.pollLogs() }
    }

    // the extension answers with at most 100 entries and keeps 500, so when a burst fills an
    // answer, ask again straight away instead of waiting a second and losing the oldest lines.
    // never two requests at once.
    private func pollLogs() {
        guard !polling, !stopping, let session = session, let data = try? JSONSerialization.data(withJSONObject: ["action": "getLogs"]) else { return }
        polling = true
        do {
            try session.sendProviderMessage(data) { response in
                DispatchQueue.main.async {
                    self.polling = false
                    guard let response = response, let logs = (try? JSONSerialization.jsonObject(with: response)) as? [[String: String]] else { return }
                    self.print(logs)
                    if logs.count >= 100 { self.pollLogs() }
                }
            }
        } catch {
            polling = false
        }
    }

    // one write per answer, not one per line. everything in an entry came from outside (process
    // names, DNS names, a proxy's reply), so it is made safe to show in a terminal first
    private func print(_ logs: [[String: String]]) {
        let now = clock.string(from: Date())
        var lines: [String] = []
        for log in logs {
            if log["type"] == "connection" {
                guard verbose >= 2 else { continue }
                lines.append("[\(now)] \(CLIText.safe(log["protocol"] ?? "?")) \(CLIText.safe(log["process"] ?? "?")) -> \(CLIText.safe(log["destination"] ?? "?")):\(CLIText.safe(log["port"] ?? "?")) via \(CLIText.safe(log["proxy"] ?? "?"))")
            } else {
                guard verbose == 1 || verbose == 3 else { continue }
                lines.append("[\(now)] [\(CLIText.safe(log["level"] ?? "INFO"))] \(CLIText.safe(log["message"] ?? ""))")
            }
        }
        if !lines.isEmpty { CLI.say(lines.joined(separator: "\n")) }
    }

    // MARK: - stopping

    // Ctrl+C, kill, and closing the Terminal window (SIGHUP) all clean up. SIGKILL can't be caught
    private func installSignalHandlers() {
        for sig in [SIGINT, SIGTERM, SIGHUP] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler { [weak self] in self?.stop(code: 0) }
            source.resume()
            signalSources.append(source)
        }
    }

    // called when our output went away
    func stopFromOutside(reason: String?) {
        DispatchQueue.main.async { self.stop(code: 0) }
    }

    private func fail(_ message: String) {
        FileHandle.standardError.write(Data(("ERROR: " + CLIText.lines(message) + "\n").utf8))
        stop(code: 1)
    }

    // clear the rules and the proxies (so nothing keeps redirecting to a stopped tool), then stop the tunnel
    private func stop(code: Int32) {
        guard !stopping else { return }
        stopping = true
        logTimer?.invalidate()
        guard let session = session else { exit(code) }
        if !started {
            // stopped while still starting: the tunnel may be up already, don't leave it running
            session.stopTunnel()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { exit(code) }
            return
        }
        CLI.say("Stopping...")
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { exit(code) }   // never hang if the extension doesn't answer
        RuleManager.clearRules(session: session) { _, _ in
            self.send(["action": "clearConfig"]) { _ in
                session.stopTunnel()
                CLI.say("Rules cleared, tunnel stopped.")
                exit(code)
            }
        }
    }
}

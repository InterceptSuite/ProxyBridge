import SwiftUI
import NetworkExtension
import UniformTypeIdentifiers
import AppKit

struct ProxyRule: Identifiable, Codable {
    var localId: String
    var name: String
    let processNames: String
    let targetHosts: String
    let targetPorts: String
    let ruleProtocol: String
    let action: String
    var enabled: Bool

    // localId is the stable gui side identity, ruleId in the extension is not stable
    var id: String { localId }

    enum CodingKeys: String, CodingKey {
        case localId
        case name
        case processNames
        case targetHosts
        case targetPorts
        case ruleProtocol = "protocol"
        case action
        case enabled
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.localId = try c.decodeIfPresent(String.self, forKey: .localId) ?? UUID().uuidString
        self.name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.processNames = try c.decode(String.self, forKey: .processNames)
        self.targetHosts = try c.decode(String.self, forKey: .targetHosts)
        self.targetPorts = try c.decode(String.self, forKey: .targetPorts)
        self.ruleProtocol = try c.decode(String.self, forKey: .ruleProtocol)
        self.action = try c.decode(String.self, forKey: .action)
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        // drop localId on export so imported rules get fresh ids
        try c.encode(name, forKey: .name)
        try c.encode(processNames, forKey: .processNames)
        try c.encode(targetHosts, forKey: .targetHosts)
        try c.encode(targetPorts, forKey: .targetPorts)
        try c.encode(ruleProtocol, forKey: .ruleProtocol)
        try c.encode(action, forKey: .action)
        try c.encode(enabled, forKey: .enabled)
    }

    init(localId: String = UUID().uuidString, name: String = "", processNames: String, targetHosts: String, targetPorts: String, ruleProtocol: String, action: String, enabled: Bool) {
        self.localId = localId
        self.name = name
        self.processNames = processNames
        self.targetHosts = targetHosts
        self.targetPorts = targetPorts
        self.ruleProtocol = ruleProtocol
        self.action = action
        self.enabled = enabled
    }

    // UserDefaults stores rules as plain dictionaries, these bridge to that
    init(dict: [String: Any]) {
        self.localId = dict["localId"] as? String ?? UUID().uuidString
        self.name = dict["name"] as? String ?? ""
        self.processNames = dict["processNames"] as? String ?? ""
        self.targetHosts = dict["targetHosts"] as? String ?? ""
        self.targetPorts = dict["targetPorts"] as? String ?? ""
        self.ruleProtocol = dict["protocol"] as? String ?? "BOTH"
        self.action = dict["action"] as? String ?? "DIRECT"
        self.enabled = dict["enabled"] as? Bool ?? true
    }

    func toDict() -> [String: Any] {
        return [
            "localId": localId,
            "name": name,
            "processNames": processNames,
            "targetHosts": targetHosts,
            "targetPorts": targetPorts,
            "protocol": ruleProtocol,
            "action": action,
            "enabled": enabled
        ]
    }
}

struct ProxyRulesView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @State private var rules: [ProxyRule] = []
    @State private var selectedRuleIds: Set<String> = []
    @State private var showAddRule = false
    @State private var editingRule: ProxyRule?
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Proxy Rules")
                    .font(.title2)
                    .fontWeight(.semibold)
                
                Spacer()
                
                Button(action: { 
                    if selectedRuleIds.count == rules.count {
                        selectedRuleIds.removeAll()
                    } else {
                        selectedRuleIds = Set(rules.map { $0.id })
                    }
                }) {
                    HStack {
                        Image(systemName: selectedRuleIds.count == rules.count ? "checkmark.square" : "square")
                        Text(selectedRuleIds.count == rules.count ? "Deselect All" : "Select All")
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .disabled(rules.isEmpty)
                
                Button(action: { exportSelectedRules() }) {
                    HStack {
                        Image(systemName: "square.and.arrow.up")
                        Text("Export")
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .disabled(selectedRuleIds.isEmpty)
                
                Button(action: { importRulesFromFile() }) {
                    HStack {
                        Image(systemName: "square.and.arrow.down")
                        Text("Import")
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                
                Button(action: { showAddRule = true }) {
                    HStack {
                        Image(systemName: "plus")
                        Text("Add Rule")
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
            
            if rules.isEmpty {
                Spacer()
                VStack(spacing: 12) {
                    Image(systemName: "list.bullet.rectangle")
                        .font(.system(size: 48))
                        .foregroundColor(.gray)
                    Text("No rules configured")
                        .font(.title3)
                        .foregroundColor(.gray)
                    Text("Click 'Add Rule' to create your first rule")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                Table(rules) {
                    TableColumn("") { rule in
                        Toggle("", isOn: Binding(
                            get: { selectedRuleIds.contains(rule.id) },
                            set: { isSelected in
                                if isSelected {
                                    selectedRuleIds.insert(rule.id)
                                } else {
                                    selectedRuleIds.remove(rule.id)
                                }
                            }
                        ))
                        .toggleStyle(.checkbox)
                        .labelsHidden()
                    }
                    .width(32)

                    TableColumn("On") { rule in
                        Toggle("", isOn: binding(for: rule))
                            .toggleStyle(.switch)
                            .labelsHidden()
                    }
                    .width(44)

                    TableColumn("") { rule in
                        HStack(spacing: 12) {
                            Button(action: { editingRule = rule }) {
                                Image(systemName: "pencil")
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(.blue)
                            .help("Edit")

                            Button(action: { deleteRule(rule) }) {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(.red)
                            .help("Delete")
                        }
                    }
                    .width(60)

                    TableColumn("SR") { rule in
                        let index = (rules.firstIndex(where: { $0.id == rule.id }) ?? 0) + 1
                        Text(verbatim: "\(index)")
                    }
                    .width(32)

                    TableColumn("Name") { rule in
                        Text(rule.name.isEmpty ? "=" : rule.name)
                            .foregroundColor(rule.name.isEmpty ? .secondary : .primary)
                    }
                    .width(min: 90, ideal: 120)

                    TableColumn("Bundle ID") { rule in
                        Text(rule.processNames.isEmpty ? "Any" : rule.processNames)
                    }
                    .width(min: 100, ideal: 140)

                    TableColumn("Target Hosts") { rule in
                        Text(rule.targetHosts.isEmpty ? "Any" : rule.targetHosts)
                    }
                    .width(min: 100, ideal: 150)

                    TableColumn("Target Ports") { rule in
                        Text(rule.targetPorts.isEmpty ? "Any" : rule.targetPorts)
                    }
                    .width(min: 70, ideal: 100)

                    TableColumn("Protocol") { rule in
                        Text(rule.ruleProtocol)
                    }
                    .width(64)

                    TableColumn("Action") { rule in
                        Text(actionDisplayName(rule.action))
                            .foregroundColor(actionColor(rule.action))
                            .fontWeight(.semibold)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .width(min: 120, ideal: 160)
                }
                .padding()
            }
        }
        .frame(minWidth: 900, minHeight: 500)
        .onAppear {
            loadRules()
        }
        // reload when the active profile changes so an open window isn't stale
        .onChange(of: viewModel.activeProfile) { _ in
            selectedRuleIds.removeAll()
            loadRules()
        }
        .sheet(isPresented: $showAddRule) {
            RuleEditorView(viewModel: viewModel, onCommit: { commitRule($0) })
        }
        .sheet(item: $editingRule) { rule in
            RuleEditorView(viewModel: viewModel, existingRule: rule, onCommit: { commitRule($0) })
        }
    }
    
    private func binding(for rule: ProxyRule) -> Binding<Bool> {
        Binding(
            get: { rule.enabled },
            set: { newValue in
                toggleRule(rule, enabled: newValue)
            }
        )
    }
    
    private func actionColor(_ action: String) -> Color {
        switch action {
        case "BLOCK": return .red
        case "DIRECT": return .blue
        case DefaultProxy.action: return viewModel.effectiveDefaultProxy == nil ? .blue : .green
        default: return .green  // any proxy config UUID
        }
    }

    private func actionDisplayName(_ action: String) -> String {
        switch action {
        case "DIRECT", "BLOCK": return action
        case DefaultProxy.action:
            if let proxy = viewModel.effectiveDefaultProxy { return "Default (\(proxy.displayName))" }
            return "Default (no proxy, goes DIRECT)"
        default:
            return viewModel.proxyConfigs.first(where: { $0.id == action })?.displayName ?? action
        }
    }
    
    // rules live in UserDefaults on the gui side, the extension is just a mirror
    private func loadRules() {
        let dicts = UserDefaults.standard.array(forKey: "proxyRules") as? [[String: Any]] ?? []
        rules = dicts.map { ProxyRule(dict: $0) }
    }

    // persist the current list and push it to the extension if the tunnel is up
    private func saveAndSync() {
        UserDefaults.standard.set(rules.map { $0.toDict() }, forKey: "proxyRules")
        if let session = viewModel.tunnelSession {
            RuleManager.resyncRules(session: session) { _, _ in }
        }
    }

    func commitRule(_ rule: ProxyRule) {
        if let index = rules.firstIndex(where: { $0.localId == rule.localId }) {
            rules[index] = rule
        } else {
            rules.append(rule)
        }
        saveAndSync()
    }

    private func deleteRule(_ rule: ProxyRule) {
        rules.removeAll { $0.localId == rule.localId }
        selectedRuleIds.remove(rule.localId)
        saveAndSync()
    }

    private func toggleRule(_ rule: ProxyRule, enabled: Bool) {
        guard let index = rules.firstIndex(where: { $0.localId == rule.localId }) else { return }
        rules[index].enabled = enabled
        saveAndSync()
    }
    
    private func getSelectedRules() -> [ProxyRule] {
        return rules.filter { selectedRuleIds.contains($0.id) }
    }
    
    private func exportSelectedRules() {
        guard !selectedRuleIds.isEmpty else { return }
        
        let selectedRules = getSelectedRules()
        
        let savePanel = NSSavePanel()
        savePanel.title = "Export Proxy Rules"
        savePanel.message = "Choose a location to save the selected rules"
        savePanel.nameFieldStringValue = "ProxyBridge-Rules.json"
        savePanel.allowedContentTypes = [.json]
        savePanel.canCreateDirectories = true
        
        let response = savePanel.runModal()
        guard response == .OK, let url = savePanel.url else { return }
        
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(selectedRules)
            try data.write(to: url)
        } catch {
            print("Export failed: \(error)")
        }
    }
    
    private func importRulesFromFile() {
        let openPanel = NSOpenPanel()
        openPanel.title = "Import Proxy Rules"
        openPanel.message = "Choose a rules file to import"
        openPanel.allowedContentTypes = [.json]
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        
        let response = openPanel.runModal()
        guard response == .OK, let url = openPanel.urls.first else { return }
        
        importRules(from: url)
    }
    
    private func importRules(from url: URL) {
        do {
            let data = try Data(contentsOf: url)
            let importedRules = try JSONDecoder().decode([ProxyRule].self, from: data)
            // decode drops localId so each imported rule already has a fresh one
            rules.append(contentsOf: importedRules)
            saveAndSync()
        } catch {
            print("Failed to import rules: \(error)")
        }
    }
}

struct RuleEditorView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    var existingRule: ProxyRule?
    var onCommit: (ProxyRule) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var ruleName: String
    @State private var processNames: String
    @State private var targetHosts: String
    @State private var targetPorts: String
    @State private var selectedProtocol: String
    @State private var selectedAction: String

    private var isEditMode: Bool { existingRule != nil }

    init(viewModel: ProxyBridgeViewModel, existingRule: ProxyRule? = nil, onCommit: @escaping (ProxyRule) -> Void) {
        self.viewModel = viewModel
        self.existingRule = existingRule
        self.onCommit = onCommit

        _ruleName = State(initialValue: existingRule?.name ?? "")
        _processNames = State(initialValue: existingRule?.processNames ?? "*")
        _targetHosts = State(initialValue: existingRule?.targetHosts ?? "*")
        _targetPorts = State(initialValue: existingRule?.targetPorts ?? "*")
        _selectedProtocol = State(initialValue: existingRule?.ruleProtocol ?? "TCP")
        // a new rule follows the default proxy when there is a proxy, otherwise it is direct
        let defaultAction = existingRule?.action ?? (viewModel.proxyConfigs.isEmpty ? "DIRECT" : DefaultProxy.action)
        _selectedAction = State(initialValue: defaultAction)
    }

    var body: some View {
        VStack(spacing: 20) {
            Text(isEditMode ? "Edit Rule" : "Add Rule")
                .font(.title2)
                .fontWeight(.semibold)

            Form {
                Section {
                    formField(
                        label: "Rule Name",
                        placeholder: "Optional, e.g. Work traffic",
                        text: $ruleName,
                        hint: "Shown in the rules list. Leave empty if you don't need one."
                    )

                    formField(
                        label: "Process / Bundle Identifier",
                        placeholder: "*",
                        text: $processNames,
                        hint: "Matches the bundle id or the process name. Examples: com.apple.Safari; curl; Google Chrome Helper; *chrome*; *"
                    )
                    
                    formField(
                        label: "Target hosts",
                        placeholder: "*",
                        text: $targetHosts,
                        hint: "IP: 127.0.0.1; 192.168.1.*; 10.0.0.1-10.0.0.254; ::1   Domain: github.com; *.github.com; *google*"
                    )
                    HStack(spacing: 4) {
                        Image(systemName: viewModel.isDNSEnabled ? "info.circle" : "exclamationmark.triangle.fill")
                            .foregroundColor(viewModel.isDNSEnabled ? .secondary : .orange)
                        Text(viewModel.isDNSEnabled
                             ? "Host names only match when Enable DNS is on in the Proxy menu. IP addresses always work."
                             : "Enable DNS is off in the Proxy menu, so host names do not match. IP addresses still work.")
                            .font(.caption).foregroundColor(.secondary)
                    }
                    
                    formField(
                        label: "Target ports",
                        placeholder: "*",
                        text: $targetPorts,
                        hint: "Example: 80; 8000-9000; 3128"
                    )

                    HStack(spacing: 4) {
                        Image(systemName: "info.circle").foregroundColor(.secondary)
                        Text("Target hosts and ports only apply to TCP. UDP rules match on the app (bundle id) only.")
                            .font(.caption).foregroundColor(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Protocol")
                            .fontWeight(.medium)
                        Picker("", selection: $selectedProtocol) {
                            Text("TCP").tag("TCP")
                            Text("UDP").tag("UDP")
                            Text("BOTH").tag("BOTH")
                        }
                        .pickerStyle(.segmented)
                        if selectedProtocol == "UDP" || selectedProtocol == "BOTH" {
                            HStack(alignment: .top, spacing: 4) {
                                Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.yellow)
                                Text("UDP only works with a SOCKS5 proxy. Not all SOCKS5 proxies support UDP by default, and SOCKS5 UDP support does not guarantee QUIC or HTTP/3 works - verify your proxy supports these separately.")
                                    .font(.caption).foregroundColor(.secondary)
                            }
                        }
                    }
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Action")
                            .fontWeight(.medium)
                        Picker("", selection: $selectedAction) {
                            Text("DIRECT").tag("DIRECT")
                            Text("BLOCK").tag("BLOCK")
                            if !viewModel.proxyConfigs.isEmpty {
                                Divider()
                                Text("Default (\(viewModel.effectiveDefaultProxy?.displayName ?? "no proxy"))").tag(DefaultProxy.action)
                                Divider()
                                ForEach(viewModel.proxyConfigs) { config in
                                    Text(config.displayName).tag(config.id)
                                }
                            }
                        }
                        .pickerStyle(.menu)
                        if selectedProtocol == "UDP" || selectedProtocol == "BOTH" {
                            let chosenId = selectedAction == DefaultProxy.action ? viewModel.effectiveDefaultProxy?.id : selectedAction
                            let isHttp = viewModel.proxyConfigs.first(where: { $0.id == chosenId })?.type.lowercased() == "http"
                            if isHttp {
                                HStack(spacing: 4) {
                                    Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.yellow)
                                    Text("UDP only works with SOCKS5 proxy. HTTP proxies do not support UDP.")
                                        .font(.caption).foregroundColor(.secondary)
                                }
                            }
                        }
                        if viewModel.proxyConfigs.isEmpty {
                            HStack(spacing: 4) {
                                Image(systemName: "info.circle").foregroundColor(.secondary)
                                Text("No proxy servers configured - add one in Proxy Settings.")
                                    .font(.caption).foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Save Rule") {
                    saveRule()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
            .padding(.horizontal)
        }
        .padding()
        .frame(width: 600, height: 620)
    }
    
    @ViewBuilder
    private func formField(label: String, placeholder: String, text: Binding<String>, hint: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label)
                .fontWeight(.medium)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
            Text(hint)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
    
    private func saveRule() {
        let rule = ProxyRule(
            localId: existingRule?.localId ?? UUID().uuidString,
            name: ruleName.trimmingCharacters(in: .whitespaces),
            processNames: processNames,
            targetHosts: targetHosts,
            targetPorts: targetPorts,
            ruleProtocol: selectedProtocol,
            action: selectedAction,
            enabled: existingRule?.enabled ?? true
        )
        onCommit(rule)
        dismiss()
    }
}

struct RulesDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    
    var rules: [ProxyRule]
    
    init(rules: [ProxyRule]) {
        self.rules = rules
    }
    
    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else {
            throw CocoaError(.fileReadCorruptFile)
        }
        let decoder = JSONDecoder()
        rules = try decoder.decode([ProxyRule].self, from: data)
    }
    
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(rules)
        return FileWrapper(regularFileWithContents: data)
    }
}

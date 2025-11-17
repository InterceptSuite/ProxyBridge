import SwiftUI
import NetworkExtension

struct ProxyRule: Identifiable {
    let id: UInt32
    let processNames: String
    let targetHosts: String
    let targetPorts: String
    let ruleProtocol: String
    let action: String
    var enabled: Bool
}

struct ProxyRulesView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @State private var rules: [ProxyRule] = []
    @State private var showAddRule = false
    @State private var editingRule: ProxyRule?
    @State private var isLoading = false
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Proxy Rules")
                    .font(.title2)
                    .fontWeight(.semibold)
                
                Spacer()
                
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
            
            if isLoading {
                Spacer()
                ProgressView()
                    .scaleEffect(1.5)
                Spacer()
            } else if rules.isEmpty {
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
                    TableColumn("Enabled") { rule in
                        Toggle("", isOn: binding(for: rule))
                            .toggleStyle(.switch)
                            .labelsHidden()
                    }
                    .width(60)
                    
                    TableColumn("Actions") { rule in
                        HStack(spacing: 8) {
                            Button(action: { editingRule = rule }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "pencil")
                                    Text("Edit")
                                }
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(.blue)
                            
                            Button(action: { deleteRule(rule) }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "trash")
                                    Text("Delete")
                                }
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(.red)
                        }
                    }
                    .width(140)
                    
                    TableColumn("SR") { rule in
                        Text("\(rule.id)")
                    }
                    .width(50)
                    
                    TableColumn("Bundle ID") { rule in
                        Text(rule.processNames.isEmpty ? "Any" : rule.processNames)
                    }
                    .width(150)
                    
                    TableColumn("Target Hosts") { rule in
                        Text(rule.targetHosts.isEmpty ? "Any" : rule.targetHosts)
                    }
                        .width(180)
                    
                    TableColumn("Target Ports") { rule in
                        Text(rule.targetPorts.isEmpty ? "Any" : rule.targetPorts)
                    }
                    .width(120)
                    
                    TableColumn("Protocol") { rule in
                        Text(rule.ruleProtocol)
                    }
                    .width(80)
                    
                    TableColumn("Action") { rule in
                        Text(rule.action)
                            .foregroundColor(actionColor(rule.action))
                            .fontWeight(.semibold)
                    }
                    .width(80)
                }
                .padding()
            }
        }
        .frame(width: 1000, height: 600)
        .onAppear {
            loadRules()
        }
        .sheet(isPresented: $showAddRule) {
            RuleEditorView(viewModel: viewModel, onSave: { loadRules() })
        }
        .sheet(item: $editingRule) { rule in
            RuleEditorView(viewModel: viewModel, existingRule: rule, onSave: { loadRules() })
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
        case "PROXY": return .green
        case "BLOCK": return .red
        case "DIRECT": return .blue
        default: return .primary
        }
    }
    
    private func loadRules() {
        guard let session = viewModel.tunnelSession else { return }
        
        isLoading = true
        RuleManager.listRules(session: session) { [self] success, rulesList in
            DispatchQueue.main.async {
                isLoading = false
                if success {
                    rules = rulesList.map(mapToProxyRule)
                }
            }
        }
    }
    
    private func mapToProxyRule(_ dict: [String: Any]) -> ProxyRule {
        ProxyRule(
            id: dict["ruleId"] as? UInt32 ?? 0,
            processNames: dict["processNames"] as? String ?? "",
            targetHosts: dict["targetHosts"] as? String ?? "",
            targetPorts: dict["targetPorts"] as? String ?? "",
            ruleProtocol: dict["protocol"] as? String ?? "BOTH",
            action: dict["action"] as? String ?? "DIRECT",
            enabled: dict["enabled"] as? Bool ?? true
        )
    }
    
    private func deleteRule(_ rule: ProxyRule) {
        guard let session = viewModel.tunnelSession else { return }
        
        RuleManager.removeRule(session: session, ruleId: rule.id) { [self] success, _ in
            if success { loadRules() }
        }
    }
    
    private func toggleRule(_ rule: ProxyRule, enabled: Bool) {
        guard let session = viewModel.tunnelSession else { return }
        
        RuleManager.toggleRule(session: session, ruleId: rule.id, enabled: enabled) { [self] _, _ in
            loadRules()
        }
    }
}

struct RuleEditorView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    var existingRule: ProxyRule?
    var onSave: () -> Void
    
    @Environment(\.dismiss) private var dismiss
    
    @State private var processNames: String
    @State private var targetHosts: String
    @State private var targetPorts: String
    @State private var selectedProtocol: String
    @State private var selectedAction: String
    
    private var isEditMode: Bool { existingRule != nil }
    
    init(viewModel: ProxyBridgeViewModel, existingRule: ProxyRule? = nil, onSave: @escaping () -> Void) {
        self.viewModel = viewModel
        self.existingRule = existingRule
        self.onSave = onSave
        
        _processNames = State(initialValue: existingRule?.processNames ?? "*")
        _targetHosts = State(initialValue: existingRule?.targetHosts ?? "*")
        _targetPorts = State(initialValue: existingRule?.targetPorts ?? "*")
        _selectedProtocol = State(initialValue: existingRule?.ruleProtocol ?? "TCP")
        _selectedAction = State(initialValue: existingRule?.action ?? "PROXY")
    }
    
    var body: some View {
        VStack(spacing: 20) {
            Text(isEditMode ? "Edit Rule" : "Add Rule")
                .font(.title2)
                .fontWeight(.semibold)
            
            Form {
                Section {
                    formField(
                        label: "Bundle Identifier (Package Name)",
                        placeholder: "*",
                        text: $processNames,
                        hint: "Example: com.apple.Safari; com.google.Chrome; com.*.browser; *"
                    )
                    
                    formField(
                        label: "Target hosts",
                        placeholder: "*",
                        text: $targetHosts,
                        hint: "Example: 127.0.0.1; *.example.com; 192.168.1.*; 10.1.0.0-10.5.255.255"
                    )
                    
                    formField(
                        label: "Target ports",
                        placeholder: "*",
                        text: $targetPorts,
                        hint: "Example: 80; 8000-9000; 3128"
                    )
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Protocol")
                            .fontWeight(.medium)
                        Picker("", selection: $selectedProtocol) {
                            Text("TCP").tag("TCP")
                            Text("UDP").tag("UDP")
                            Text("BOTH").tag("BOTH")
                        }
                        .pickerStyle(.segmented)
                    }
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Action")
                            .fontWeight(.medium)
                        Picker("", selection: $selectedAction) {
                            Text("PROXY").tag("PROXY")
                            Text("DIRECT").tag("DIRECT")
                            Text("BLOCK").tag("BLOCK")
                        }
                        .pickerStyle(.segmented)
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
        .frame(width: 600, height: 550)
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
        guard let session = viewModel.tunnelSession else { return }
        
        if let existing = existingRule {
            updateExistingRule(session: session, ruleId: existing.id)
        } else {
            addNewRule(session: session)
        }
    }
    
    private func updateExistingRule(session: NETunnelProviderSession, ruleId: UInt32) {
        RuleManager.updateRule(
            session: session,
            ruleId: ruleId,
            processNames: processNames,
            targetHosts: targetHosts,
            targetPorts: targetPorts,
            protocol: selectedProtocol,
            action: selectedAction,
            enabled: true
        ) { [self] success, _ in
            if success { dismissOnSuccess() }
        }
    }
    
    private func addNewRule(session: NETunnelProviderSession) {
        RuleManager.addRule(
            session: session,
            processNames: processNames,
            targetHosts: targetHosts,
            targetPorts: targetPorts,
            protocol: selectedProtocol,
            action: selectedAction,
            enabled: true
        ) { [self] success, _, _ in
            if success { dismissOnSuccess() }
        }
    }
    
    private func dismissOnSuccess() {
        DispatchQueue.main.async {
            onSave()
            dismiss()
        }
    }
}

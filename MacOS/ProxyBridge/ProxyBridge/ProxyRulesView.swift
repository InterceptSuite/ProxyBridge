//
//  ProxyRulesView.swift
//  ProxyBridge
//
//  Created by sourav kalal on 14/11/25.
//

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
    
    var ruleId: UInt32 { id }
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
                Text("Process Rules")
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
                    
                    TableColumn("Process") { rule in
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
        RuleManager.listRules(session: session) { success, rulesList in
            DispatchQueue.main.async {
                isLoading = false
                if success {
                    rules = rulesList.map { dict in
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
                }
            }
        }
    }
    
    private func deleteRule(_ rule: ProxyRule) {
        guard let session = viewModel.tunnelSession else { return }
        
        RuleManager.removeRule(session: session, ruleId: rule.id) { success, message in
            if success {
                loadRules()
            }
        }
    }
    
    private func toggleRule(_ rule: ProxyRule, enabled: Bool) {
        guard let session = viewModel.tunnelSession else { return }
        
        RuleManager.toggleRule(
            session: session,
            ruleId: rule.id,
            enabled: enabled
        ) { _, _ in
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
            Text(existingRule == nil ? "Add Rule" : "Edit Rule")
                .font(.title2)
                .fontWeight(.semibold)
            
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Applications")
                            .fontWeight(.medium)
                        TextField("*", text: $processNames)
                            .textFieldStyle(.roundedBorder)
                        Text("Example: iexplore.exe; \"C:\\some app.exe\"; fire*.exe; *.bin")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Target hosts")
                            .fontWeight(.medium)
                        TextField("*", text: $targetHosts)
                            .textFieldStyle(.roundedBorder)
                        Text("Example: 127.0.0.1; *.example.com; 192.168.1.*; 10.1.0.0-10.5.255.255")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Target ports")
                            .fontWeight(.medium)
                        TextField("*", text: $targetPorts)
                            .textFieldStyle(.roundedBorder)
                        Text("Example: 80; 8000-9000; 3128")
                            .font(.caption)
                            .foregroundColor(.secondary)
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
    
    private func saveRule() {
        guard let session = viewModel.tunnelSession else { return }
        
        if let existing = existingRule {
            // Edit existing rule - use update
            RuleManager.updateRule(
                session: session,
                ruleId: existing.id,
                processNames: processNames,
                targetHosts: targetHosts,
                targetPorts: targetPorts,
                protocol: selectedProtocol,
                action: selectedAction,
                enabled: true
            ) { success, _ in
                if success {
                    DispatchQueue.main.async {
                        onSave()
                        dismiss()
                    }
                }
            }
        } else {
            RuleManager.addRule(
                session: session,
                processNames: processNames,
                targetHosts: targetHosts,
                targetPorts: targetPorts,
                protocol: selectedProtocol,
                action: selectedAction,
                enabled: true
            ) { success, _, _ in
                if success {
                    DispatchQueue.main.async {
                        onSave()
                        dismiss()
                    }
                }
            }
        }
    }
}

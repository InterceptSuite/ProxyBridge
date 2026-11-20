import SwiftUI

struct RulesView: View {
    @EnvironmentObject private var model: ConfigModel
    @State private var editing: ProxyRule?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("Default", selection: Binding(
                        get: { model.config.defaultAction },
                        set: { model.setDefaultAction($0) }
                    )) {
                        ForEach(RuleAction.allCases, id: \.self) { Text($0.label) }
                    }
                } footer: {
                    Text("Used for traffic that matches no rule. Rules are checked from top to bottom.")
                }

                Section("Rules") {
                    if model.config.rules.isEmpty {
                        Text("No rules yet").foregroundStyle(.secondary)
                    }
                    ForEach(model.config.rules) { rule in
                        Button { editing = rule } label: {
                            RuleRow(rule: rule, proxyName: model.proxyName(for: rule.proxyId))
                        }
                        .tint(.primary)
                    }
                    .onDelete { model.deleteRules(at: $0) }
                    .onMove { model.moveRules(from: $0, to: $1) }
                }
            }
            .navigationTitle("Rules")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { EditButton() }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Add", systemImage: "plus") { editing = ProxyRule() }
                }
            }
            .sheet(item: $editing) { rule in
                RuleEditor(rule: rule)
            }
        }
    }
}

private struct RuleRow: View {
    let rule: ProxyRule
    let proxyName: String

    private var details: String {
        let ports = rule.ports.isEmpty ? "any port" : rule.ports
        let action = rule.action == .proxy ? "Proxy: \(proxyName)" : rule.action.label
        return [ports, rule.proto.label, action].joined(separator: ", ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(rule.title)
            Text(details)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .opacity(rule.enabled ? 1 : 0.5)
    }
}

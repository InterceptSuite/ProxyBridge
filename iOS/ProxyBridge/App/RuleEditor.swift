import SwiftUI

struct RuleEditor: View {
    @EnvironmentObject private var model: ConfigModel
    @Environment(\.dismiss) private var dismiss
    @State private var rule: ProxyRule

    init(rule: ProxyRule) {
        _rule = State(initialValue: rule)
    }

    private var udpWillBypassProxy: Bool {
        let chosen = model.config.proxies.first { $0.id == rule.proxyId } ?? model.config.proxies.first
        return chosen?.kind == .http && rule.proto != .tcp
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name (optional)", text: $rule.name)
                    Toggle("Enabled", isOn: $rule.enabled)
                }

                Section {
                    TextField("github.com; *.example.com; 10.0.0.0/8", text: $rule.hosts, axis: .vertical)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                } header: {
                    Text("Hosts")
                } footer: {
                    Text("Domains, IP addresses or CIDR blocks separated by semicolons. Leave empty to match any host. A domain only matches when the app looked it up through the system DNS, so apps with their own encrypted DNS are matched by IP only.")
                }

                Section {
                    TextField("443; 80", text: $rule.ports)
                        .keyboardType(.numbersAndPunctuation)
                    Picker("Protocol", selection: $rule.proto) {
                        ForEach(RuleProtocol.allCases, id: \.self) { Text($0.label) }
                    }
                } header: {
                    Text("Ports and protocol")
                } footer: {
                    Text("Leave the ports empty to match any port.")
                }

                Section("Action") {
                    Picker("Action", selection: $rule.action) {
                        ForEach(RuleAction.allCases, id: \.self) { Text($0.label) }
                    }
                    .pickerStyle(.segmented)

                    if rule.action == .proxy {
                        Picker("Proxy", selection: $rule.proxyId) {
                            Text("Default proxy").tag(UUID?.none)
                            ForEach(model.config.proxies) { Text($0.displayName).tag(UUID?.some($0.id)) }
                        }
                        if udpWillBypassProxy {
                            Text("An HTTP proxy cannot carry UDP. UDP traffic matched by this rule goes direct.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle(rule.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        model.save(rule)
                        dismiss()
                    }
                }
            }
        }
    }
}

import SwiftUI

struct ProxyEditor: View {
    @EnvironmentObject private var model: ConfigModel
    @Environment(\.dismiss) private var dismiss
    @State private var proxy: ProxyConfig

    init(proxy: ProxyConfig) {
        _proxy = State(initialValue: proxy)
    }

    private var isValid: Bool {
        !proxy.host.trimmingCharacters(in: .whitespaces).isEmpty && (1...65535).contains(proxy.port)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name (optional)", text: $proxy.name)
                    Picker("Type", selection: $proxy.kind) {
                        ForEach(ProxyKind.allCases, id: \.self) { Text($0.label) }
                    }
                    .pickerStyle(.segmented)
                }

                Section("Server") {
                    TextField("Host", text: $proxy.host)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    TextField("Port", value: $proxy.port, format: .number.grouping(.never))
                        .keyboardType(.numberPad)
                }

                Section {
                    TextField("User name", text: $proxy.username)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    SecureField("Password", text: $proxy.password)
                } header: {
                    Text("Authentication")
                } footer: {
                    Text("Optional. Leave the user name empty if the proxy needs no login.")
                }
            }
            .navigationTitle(proxy.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        proxy.host = proxy.host.trimmingCharacters(in: .whitespaces)
                        model.save(proxy)
                        dismiss()
                    }
                    .disabled(!isValid)
                }
            }
        }
    }
}

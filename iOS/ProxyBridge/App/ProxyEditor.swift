import SwiftUI

struct ProxyEditor: View {
    @EnvironmentObject private var model: ConfigModel
    @Environment(\.dismiss) private var dismiss
    @State private var proxy: ProxyConfig
    @State private var portText: String

    init(proxy: ProxyConfig) {
        _proxy = State(initialValue: proxy)
        _portText = State(initialValue: String(proxy.port))
    }

    private var port: Int? {
        Int(portText).flatMap { (1...65535).contains($0) ? $0 : nil }
    }

    private var isValid: Bool {
        !proxy.host.trimmingCharacters(in: .whitespaces).isEmpty && port != nil
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
                    TextField("Port", text: $portText)
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
                        proxy.port = port ?? proxy.port
                        model.save(proxy)
                        dismiss()
                    }
                    .disabled(!isValid)
                }
            }
        }
    }
}

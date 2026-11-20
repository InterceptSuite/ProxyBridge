import SwiftUI

struct StatusView: View {
    @EnvironmentObject private var tunnel: TunnelManager
    @EnvironmentObject private var model: ConfigModel

    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(isOn: Binding(
                        get: { tunnel.isOn },
                        set: { enabled in Task { await tunnel.setEnabled(enabled) } }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("ProxyBridge")
                            Text(tunnel.status.label)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .disabled(tunnel.isBusy)

                    if let message = tunnel.errorMessage {
                        Text(message).foregroundStyle(.red)
                    }
                } footer: {
                    if model.config.proxies.isEmpty {
                        Text("Add a proxy in the Proxies tab, then create rules to choose which traffic uses it.")
                    } else {
                        Text("Rules apply to the whole device. iOS does not say which app a connection belongs to, so rules match the destination only.")
                    }
                }

                Section {
                    LabeledContent("Version", value: version)
                    Link("Website", destination: URL(string: "https://proxybridge.interceptsuite.com/")!)
                } header: {
                    Text("About")
                } footer: {
                    Text("Traffic is sent only to the proxies you add. ProxyBridge collects no data and has no analytics.")
                }
            }
            .navigationTitle("ProxyBridge")
        }
    }
}

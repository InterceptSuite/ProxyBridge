import SwiftUI
import Darwin

struct ProxySettingsView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var showAddProxy = false
    @State private var editingConfig: ProxyBridgeViewModel.ProxyConfig?
    @State private var deletingConfig: ProxyBridgeViewModel.ProxyConfig?
    @State private var affectedRulesCount = 0
    @State private var testResults: [String: String] = [:]

    var body: some View {
        VStack(spacing: 0) {
            headerView
            Divider()
            listContent
            Divider()
            footerButtons
        }
        .frame(minWidth: 760, idealWidth: 760, maxWidth: .infinity, minHeight: 440, idealHeight: 480, maxHeight: .infinity)
        .alert("Delete Proxy?", isPresented: Binding(
            get: { deletingConfig != nil },
            set: { if !$0 { deletingConfig = nil } }
        )) {
            Button("Delete", role: .destructive) {
                if let c = deletingConfig { viewModel.removeProxyConfig(c) }
                deletingConfig = nil
            }
            Button("Cancel", role: .cancel) { deletingConfig = nil }
        } message: {
            if affectedRulesCount > 0 {
                Text("\(affectedRulesCount) rule\(affectedRulesCount == 1 ? "" : "s") use this proxy and will be set to Direct.")
            } else {
                Text("This proxy will be permanently removed.")
            }
        }
        .sheet(isPresented: $showAddProxy) {
            ProxyConfigEditorView(viewModel: viewModel, existing: nil)
        }
        .sheet(item: $editingConfig) { config in
            ProxyConfigEditorView(viewModel: viewModel, existing: config)
        }
    }

    private var headerView: some View {
        HStack {
            Image(systemName: "network")
                .font(.title2)
                .foregroundColor(.accentColor)
            Text("Proxy Settings")
                .font(.title2)
                .fontWeight(.semibold)
            Spacer()
            Button(action: { showAddProxy = true }) {
                HStack(spacing: 4) {
                    Image(systemName: "plus")
                    Text("Add")
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
    }

    @ViewBuilder
    private var listContent: some View {
        if viewModel.proxyConfigs.isEmpty {
            Spacer()
            VStack(spacing: 12) {
                Image(systemName: "network.slash")
                    .font(.system(size: 48))
                    .foregroundColor(.gray)
                Text("No proxy servers configured")
                    .font(.title3)
                    .foregroundColor(.gray)
                Text("Click 'Add' to configure your first proxy server")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            Spacer()
        } else {
            Table(viewModel.proxyConfigs) {
                TableColumn("Type") { config in
                    Text(config.type.uppercased())
                        .foregroundColor(typeColor(config.type))
                        .fontWeight(.semibold)
                }
                .width(70)

                TableColumn("Server") { config in
                    Text("\(config.host):\(config.port)")
                        .fontDesign(.monospaced)
                }
                .width(min: 180, ideal: 220, max: .infinity)

                TableColumn("Auth") { config in
                    if config.username != nil {
                        Image(systemName: "lock.fill").foregroundColor(.secondary)
                    } else {
                        Text("—").foregroundColor(.secondary)
                    }
                }
                .width(40)

                TableColumn("Test") { config in
                    HStack(spacing: 6) {
                        Button(action: { testConnection(config) }) {
                            Label("Test", systemImage: "link")
                        }
                        .buttonStyle(.borderless)
                        if let result = testResults[config.id] {
                            Text(result)
                                .font(.caption2)
                                .foregroundColor(result == "OK" ? .green : .red)
                        }
                    }
                }
                .width(min: 80, ideal: 100)

                TableColumn("") { config in
                    HStack(spacing: 12) {
                        Button(action: { editingConfig = config }) {
                            Image(systemName: "pencil")
                        }
                        .buttonStyle(.borderless)
                        .foregroundColor(.blue)
                        .help("Edit")

                        Button(action: { confirmDelete(config) }) {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .foregroundColor(.red)
                        .help("Delete")
                    }
                }
                .width(60)
            }
            .padding()
        }
    }

    private var footerButtons: some View {
        HStack {
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
    }

    private func confirmDelete(_ config: ProxyBridgeViewModel.ProxyConfig) {
        affectedRulesCount = viewModel.rulesUsingProxy(id: config.id)
        deletingConfig = config
    }

    private func typeColor(_ type: String) -> Color {
        type.lowercased() == "socks5" ? .cyan : .orange
    }

    private func testConnection(_ config: ProxyBridgeViewModel.ProxyConfig) {
        testResults[config.id] = "..."
        DispatchQueue.global().async {
            let result = checkTCPReachability(host: config.host, port: config.port)
            DispatchQueue.main.async {
                testResults[config.id] = result ? "OK" : "FAIL"
            }
        }
    }

    private func checkTCPReachability(host: String, port: Int) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { Darwin.close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)

        return withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
    }
}

struct ProxyConfigEditorView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    var existing: ProxyBridgeViewModel.ProxyConfig?
    @Environment(\.dismiss) private var dismiss

    @State private var proxyType = "socks5"
    @State private var proxyHost = ""
    @State private var proxyPort = ""
    @State private var username = ""
    @State private var password = ""
    @State private var validationError = ""

    private let proxyTypes = ["http", "socks5"]
    private var isSaveDisabled: Bool {
        proxyHost.isEmpty || proxyPort.isEmpty || !validationError.isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "network")
                    .font(.title2)
                    .foregroundColor(.accentColor)
                Text(existing == nil ? "Add Proxy" : "Edit Proxy")
                    .font(.title2)
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            Form {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack { Text("Proxy Type").fontWeight(.medium); Text("*").foregroundColor(.red) }
                        Picker("Select proxy type", selection: $proxyType) {
                            ForEach(proxyTypes, id: \.self) { type in
                                Text(type.uppercased()).tag(type)
                            }
                        }
                        .pickerStyle(.menu)
                    }
                    .padding(.vertical, 8)

                    formTextField(label: "Proxy IP/Domain", placeholder: "127.0.0.1 or proxy.example.com", text: $proxyHost, required: true)
                        .onChange(of: proxyHost) { _ in validateInputs() }
                    formTextField(label: "Proxy Port", placeholder: "1080", text: $proxyPort, required: true)
                        .onChange(of: proxyPort) { _ in validateInputs() }
                    formTextField(label: "Username", placeholder: "Leave empty if no auth", text: $username)
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Password").fontWeight(.medium)
                        SecureField("Leave empty if no auth", text: $password)
                            .textFieldStyle(.roundedBorder)
                    }
                    .padding(.vertical, 8)

                    if !validationError.isEmpty {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red)
                            Text(validationError).font(.caption).foregroundColor(.red)
                        }
                        .padding(.top, 4)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack(spacing: 12) {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") { save(); dismiss() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaveDisabled)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
        }
        .frame(width: 500, height: 520)
        .onAppear {
            if let e = existing {
                proxyType = e.type
                proxyHost = e.host
                proxyPort = String(e.port)
                username = e.username ?? ""
                password = e.password ?? ""
            }
            validateInputs()
        }
    }

    @ViewBuilder
    private func formTextField(label: String, placeholder: String, text: Binding<String>, required: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(label).fontWeight(.medium)
                if required { Text("*").foregroundColor(.red) }
            }
            TextField(placeholder, text: text).textFieldStyle(.roundedBorder)
        }
        .padding(.vertical, 8)
    }

    private func validateInputs() {
        if !proxyHost.isEmpty {
            let validCharsIPv6 = CharacterSet(charactersIn: "0123456789abcdefABCDEF:")
            let isIPv6 = proxyHost.rangeOfCharacter(from: validCharsIPv6.inverted) == nil && proxyHost.contains(":")
            let ipv4Parts = proxyHost.split(separator: ".")
            let isIPv4 = ipv4Parts.count == 4 && ipv4Parts.allSatisfy { Int($0).map { $0 >= 0 && $0 <= 255 } ?? false }
            let domainPattern = "^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$"
            let isDomain = NSPredicate(format: "SELF MATCHES %@", domainPattern).evaluate(with: proxyHost) || proxyHost == "localhost"
            if !isIPv4 && !isIPv6 && !isDomain {
                validationError = "Invalid proxy IP/domain"
                return
            }
        }
        if !proxyPort.isEmpty {
            if let port = Int(proxyPort) {
                if port < 1 || port > 65535 {
                    validationError = "Port must be between 1 and 65535"
                    return
                }
            } else {
                validationError = "Port must be a valid number"
                return
            }
        }
        validationError = ""
    }

    private func save() {
        guard let port = Int(proxyPort) else { return }
        let config = ProxyBridgeViewModel.ProxyConfig(
            id: existing?.id ?? UUID().uuidString,
            type: proxyType,
            host: proxyHost,
            port: port,
            username: username.isEmpty ? nil : username,
            password: password.isEmpty ? nil : password
        )
        if existing != nil {
            viewModel.updateProxyConfig(config)
        } else {
            viewModel.addProxyConfig(config)
        }
    }
}

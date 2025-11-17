import SwiftUI

struct ProxySettingsView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @Environment(\.dismiss) private var dismiss
    
    @State private var proxyType = ""
    @State private var proxyHost = ""
    @State private var proxyPort = ""
    @State private var username = ""
    @State private var password = ""
    @State private var validationError = ""
    
    private let proxyTypes = ["http", "socks5"]
    private var isSaveDisabled: Bool {
        proxyType.isEmpty || proxyHost.isEmpty || proxyPort.isEmpty || !validationError.isEmpty
    }
    
    var body: some View {
        VStack(spacing: 0) {
            headerView
            formContent
            Divider()
            footerButtons
        }
        .frame(width: 600, height: 500)
        .onAppear(perform: loadCurrentSettings)
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
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    private var formContent: some View {
        Form {
            Section {
                formPicker(label: "Proxy Type", selection: $proxyType, required: true)
                formTextField(label: "Proxy IP/Domain", placeholder: "127.0.0.1 or proxy.example.com", text: $proxyHost, required: true)
                    .onChange(of: proxyHost) { _ in validateInputs() }
                formTextField(label: "Proxy Port", placeholder: "8080", text: $proxyPort, required: true)
                    .onChange(of: proxyPort) { _ in validateInputs() }
                formTextField(label: "Username", placeholder: "Leave empty if no auth required", text: $username)
                formSecureField(label: "Password", placeholder: "Leave empty if no auth required", text: $password)
                
                if !validationError.isEmpty {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text(validationError)
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                    .padding(.top, 4)
                }
                
                HStack {
                    Text("* Required fields")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .padding(.top, 4)
            }
        }
        .formStyle(.grouped)
    }
    
    private var footerButtons: some View {
        HStack(spacing: 12) {
            Spacer()
            Button("Cancel") {
                dismiss()
            }
            .keyboardShortcut(.cancelAction)
            
            Button("Save Changes") {
                saveSettings()
                dismiss()
            }
            .buttonStyle(.borderedProminent)
            .keyboardShortcut(.defaultAction)
            .disabled(isSaveDisabled)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
    }
    
    @ViewBuilder
    private func formPicker(label: String, selection: Binding<String>, required: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            labelWithRequiredMark(label: label, required: required)
            Picker("Select proxy type", selection: selection) {
                Text("Select proxy type").tag("")
                ForEach(proxyTypes, id: \.self) { type in
                    Text(type.uppercased()).tag(type)
                }
            }
            .pickerStyle(.menu)
        }
        .padding(.vertical, 8)
    }
    
    @ViewBuilder
    private func formTextField(label: String, placeholder: String, text: Binding<String>, required: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            labelWithRequiredMark(label: label, required: required)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
        }
        .padding(.vertical, 8)
    }
    
    @ViewBuilder
    private func formSecureField(label: String, placeholder: String, text: Binding<String>, required: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            labelWithRequiredMark(label: label, required: required)
            SecureField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
        }
        .padding(.vertical, 8)
    }
    
    @ViewBuilder
    private func labelWithRequiredMark(label: String, required: Bool) -> some View {
        HStack {
            Text(label)
                .fontWeight(.medium)
            if required {
                Text("*")
                    .foregroundColor(.red)
            }
        }
    }
    
    private func loadCurrentSettings() {
        if let config = viewModel.proxyConfig {
            proxyType = config.type
            proxyHost = config.host
            proxyPort = String(config.port)
            username = config.username ?? ""
            password = config.password ?? ""
        }
        validateInputs()
    }
    
    private func validateInputs() {
        if !proxyHost.isEmpty && !isValidHost(proxyHost) {
            validationError = "Invalid proxy IP/domain"
            return
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
    
    private func isValidHost(_ host: String) -> Bool {
        if isValidIPv4(host) {
            return true
        }
        
        if isValidIPv6(host) {
            return true
        }
        
        if isValidDomain(host) {
            return true
        }
        
        return false
    }
    
    private func isValidIPv4(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return false }
        
        for part in parts {
            guard let num = Int(part), num >= 0 && num <= 255 else {
                return false
            }
        }
        return true
    }
    
    private func isValidIPv6(_ ip: String) -> Bool {
        let validChars = CharacterSet(charactersIn: "0123456789abcdefABCDEF:")
        return ip.rangeOfCharacter(from: validChars.inverted) == nil && ip.contains(":")
    }
    
    private func isValidDomain(_ domain: String) -> Bool {
        let domainPattern = "^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$"
        let predicate = NSPredicate(format: "SELF MATCHES %@", domainPattern)
        return predicate.evaluate(with: domain) || domain == "localhost"
    }
    
    private func saveSettings() {
        guard let port = Int(proxyPort) else { return }
        
        let config = ProxyBridgeViewModel.ProxyConfig(
            type: proxyType,
            host: proxyHost,
            port: port,
            username: username.isEmpty ? nil : username,
            password: password.isEmpty ? nil : password
        )
        
        viewModel.setProxyConfig(config)
    }
}

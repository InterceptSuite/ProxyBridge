//
//  ProxySettingsView.swift
//  ProxyBridge
//
//  Created by sourav kalal on 14/11/25.
//

import SwiftUI

struct ProxySettingsView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @Environment(\.dismiss) private var dismiss
    
    @State private var proxyType = ""
    @State private var proxyHost = ""
    @State private var proxyPort = ""
    @State private var username = ""
    @State private var password = ""
    
    let proxyTypes = ["http", "socks5"]
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
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
            
            // Form Content
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Proxy Type")
                                .fontWeight(.medium)
                            Text("*")
                                .foregroundColor(.red)
                        }
                        Picker("Select proxy type", selection: $proxyType) {
                            Text("Select proxy type").tag("")
                            ForEach(proxyTypes, id: \.self) { type in
                                Text(type.uppercased()).tag(type)
                            }
                        }
                        .pickerStyle(.menu)
                    }
                    .padding(.vertical, 8)
                    
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Proxy IP Address")
                                .fontWeight(.medium)
                            Text("*")
                                .foregroundColor(.red)
                        }
                        TextField("127.0.0.1", text: $proxyHost)
                            .textFieldStyle(.roundedBorder)
                    }
                    .padding(.vertical, 8)
                    
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Proxy Port")
                                .fontWeight(.medium)
                            Text("*")
                                .foregroundColor(.red)
                        }
                        TextField("8080", text: $proxyPort)
                            .textFieldStyle(.roundedBorder)
                    }
                    .padding(.vertical, 8)
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Username (Optional)")
                            .fontWeight(.medium)
                        TextField("Leave empty if no auth required", text: $username)
                            .textFieldStyle(.roundedBorder)
                    }
                    .padding(.vertical, 8)
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Password (Optional)")
                            .fontWeight(.medium)
                        SecureField("Leave empty if no auth required", text: $password)
                            .textFieldStyle(.roundedBorder)
                    }
                    .padding(.vertical, 8)
                    
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
            
            Divider()
            
            // Footer Buttons
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
                .disabled(proxyType.isEmpty || proxyHost.isEmpty || proxyPort.isEmpty)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
        }
        .frame(width: 600, height: 500)
        .onAppear {
            loadCurrentSettings()
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

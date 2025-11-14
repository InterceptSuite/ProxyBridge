//
//  ProxySettingsView.swift
//  ProxyBridge
//
//  Created by sourav kalal on 14/11/25.
//

import SwiftUI

struct ProxySettingsView: View {
    @ObservedObject var viewModel: ProxyBridgeViewModel
    @State private var proxyType = "socks5"
    @State private var proxyHost = ""
    @State private var proxyPort = "1080"
    @State private var username = ""
    @State private var password = ""
    
    let proxyTypes = ["socks5", "http"]
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Proxy Settings")
                .font(.title2)
                .fontWeight(.semibold)
                .padding(.top)
            
            Form {
                Picker("Proxy Type:", selection: $proxyType) {
                    ForEach(proxyTypes, id: \.self) { type in
                        Text(type.uppercased()).tag(type)
                    }
                }
                .pickerStyle(.segmented)
                
                TextField("Proxy Host:", text: $proxyHost)
                    .textFieldStyle(.roundedBorder)
                
                TextField("Proxy Port:", text: $proxyPort)
                    .textFieldStyle(.roundedBorder)
                
                TextField("Username (optional):", text: $username)
                    .textFieldStyle(.roundedBorder)
                
                SecureField("Password (optional):", text: $password)
                    .textFieldStyle(.roundedBorder)
            }
            .padding()
            
            HStack {
                Spacer()
                
                Button("Save Changes") {
                    saveSettings()
                }
                .buttonStyle(.borderedProminent)
                .disabled(proxyHost.isEmpty || proxyPort.isEmpty)
                
                Spacer()
            }
            .padding(.bottom)
        }
        .frame(width: 500, height: 400)
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

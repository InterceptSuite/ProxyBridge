import SwiftUI

struct AboutView: View {
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        VStack(spacing: 20) {
            Text("ProxyBridge")
                .font(.system(size: 28, weight: .bold))
                .foregroundColor(.accentColor)
            
            Text("Version 3.0")
                .font(.system(size: 14))
                .foregroundColor(.secondary)
            
            Text("Universal proxy client for macOS applications")
                .font(.system(size: 14))
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.bottom, 8)
            
            Text("Author: Sourav Kalal / InterceptSuite")
                .font(.system(size: 13))
                .foregroundColor(.secondary)
                .padding(.top, 4)
            
            VStack(spacing: 12) {
                HStack {
                    Text("Website:")
                        .foregroundColor(.secondary)
                    Link("interceptsuite.com", destination: URL(string: "https://interceptsuite.com")!)
                        .foregroundColor(.accentColor)
                }
                
                HStack {
                    Text("GitHub:")
                        .foregroundColor(.secondary)
                    Link("github.com/InterceptSuite/ProxyBridge", destination: URL(string: "https://github.com/InterceptSuite/ProxyBridge")!)
                        .foregroundColor(.accentColor)
                }
            }
            .font(.system(size: 13))
            
            Text("License: MIT")
                .font(.system(size: 13))
                .foregroundColor(.secondary)
                .padding(.top, 8)
            
            Button("Close") {
                dismiss()
            }
            .keyboardShortcut(.defaultAction)
            .padding(.top, 12)
        }
        .padding(32)
        .frame(width: 400, height: 350)
    }
}

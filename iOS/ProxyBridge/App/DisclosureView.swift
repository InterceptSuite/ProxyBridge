import SwiftUI

/// Shown once before the tunnel can be used. App Review guideline 5.4 asks a VPN app to state, on a screen of the app
/// and before the service is used, what data is collected and how it is used.
struct DisclosureView: View {
    /// Raise this when the text changes, so everyone has to read it again.
    static let version = 1

    let onAccept: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    Text("Before you start")
                        .font(.largeTitle.bold())
                    section("What it does",
                            "ProxyBridge sends the network traffic of this device through the SOCKS5 or HTTP proxies you add, using an iOS VPN connection. iOS asks you to allow it the first time you turn it on.")
                    section("Your traffic",
                            "Traffic you send through a proxy goes to that proxy, and whoever runs it can see it. Traffic you send direct goes straight to its destination. None of it is sent to us. Name lookups go to the DNS servers of your network, or to public ones if none can be found.")
                    section("Data we collect",
                            "None. ProxyBridge has no account, no analytics, no advertising and no tracking. Your proxies, passwords and rules stay on this device.")
                    section("Sharing",
                            "We do not sell, use or disclose any data to third parties.")
                    section("Site names",
                            "To match rules written for a domain, ProxyBridge reads the names in this device's DNS lookups while it is on. They are kept in memory only and are never stored or sent anywhere.")
                    Link("Read the privacy policy", destination: Links.privacyPolicy)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(24)
            }
            Button(action: onAccept) {
                Text("Continue").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(24)
        }
    }

    private func section(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            Text(text).foregroundStyle(.secondary)
        }
    }
}

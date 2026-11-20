import SwiftUI

struct RootView: View {
    var body: some View {
        TabView {
            StatusView()
                .tabItem { Label("Status", systemImage: "power") }
            RulesView()
                .tabItem { Label("Rules", systemImage: "list.bullet") }
            ProxiesView()
                .tabItem { Label("Proxies", systemImage: "server.rack") }
        }
    }
}

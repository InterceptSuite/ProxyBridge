import SwiftUI

struct RootView: View {
    @AppStorage("acceptedDisclosureVersion") private var acceptedVersion = 0

    var body: some View {
        TabView {
            StatusView()
                .tabItem { Label("Status", systemImage: "power") }
            RulesView()
                .tabItem { Label("Rules", systemImage: "list.bullet") }
            ProxiesView()
                .tabItem { Label("Proxies", systemImage: "server.rack") }
        }
        .fullScreenCover(isPresented: Binding(get: { acceptedVersion < DisclosureView.version }, set: { _ in })) {
            DisclosureView { acceptedVersion = DisclosureView.version }
        }
    }
}

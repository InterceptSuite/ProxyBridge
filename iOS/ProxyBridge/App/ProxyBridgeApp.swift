import SwiftUI

@main
struct ProxyBridgeApp: App {
    @StateObject private var tunnel: TunnelManager
    @StateObject private var model: ConfigModel

    init() {
        let tunnel = TunnelManager()
        _tunnel = StateObject(wrappedValue: tunnel)
        _model = StateObject(wrappedValue: ConfigModel(tunnel: tunnel))
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(tunnel)
                .environmentObject(model)
                .task { await tunnel.load() }
        }
    }
}

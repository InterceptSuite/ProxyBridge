import SwiftUI

struct ProxiesView: View {
    @EnvironmentObject private var model: ConfigModel
    @State private var editing: ProxyConfig?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if model.config.proxies.isEmpty {
                        Text("No proxies yet").foregroundStyle(.secondary)
                    }
                    ForEach(model.config.proxies) { proxy in
                        Button { editing = proxy } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(proxy.displayName)
                                Text("\(proxy.kind.label), \(proxy.host):\(proxy.port)")
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .tint(.primary)
                    }
                    .onDelete { model.deleteProxies(at: $0) }
                    .onMove { model.moveProxies(from: $0, to: $1) }
                } footer: {
                    Text("The first proxy is the default one, used by rules that do not name a proxy.")
                }
            }
            .navigationTitle("Proxies")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { EditButton() }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Add", systemImage: "plus") { editing = ProxyConfig() }
                }
            }
            .sheet(item: $editing) { proxy in
                ProxyEditor(proxy: proxy)
            }
        }
    }
}

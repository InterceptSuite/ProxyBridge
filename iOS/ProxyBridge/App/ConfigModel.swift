import Foundation

/// The config the screens edit. Every change is saved and sent to a running tunnel.
@MainActor
final class ConfigModel: ObservableObject {
    @Published private(set) var config: AppConfig

    private let tunnel: TunnelManager

    init(tunnel: TunnelManager) {
        self.tunnel = tunnel
        config = ConfigStore.shared.load()
    }

    // MARK: rules

    func save(_ rule: ProxyRule) {
        update { Self.upsert(rule, in: &$0.rules) }
    }

    func deleteRules(at offsets: IndexSet) {
        update { $0.rules.remove(atOffsets: offsets) }
    }

    func moveRules(from source: IndexSet, to destination: Int) {
        update { $0.rules.move(fromOffsets: source, toOffset: destination) }
    }

    func setDefaultAction(_ action: RuleAction) {
        update { $0.defaultAction = action }
    }

    // MARK: proxies

    func save(_ proxy: ProxyConfig) {
        update { Self.upsert(proxy, in: &$0.proxies) }
    }

    func deleteProxies(at offsets: IndexSet) {
        update { config in
            let removed = Set(offsets.map { config.proxies[$0].id })
            config.proxies.remove(atOffsets: offsets)
            // a rule that pointed at a deleted proxy falls back to the default one
            for index in config.rules.indices where removed.contains(config.rules[index].proxyId ?? UUID()) {
                config.rules[index].proxyId = nil
            }
        }
    }

    func moveProxies(from source: IndexSet, to destination: Int) {
        update { $0.proxies.move(fromOffsets: source, toOffset: destination) }
    }

    func proxyName(for id: UUID?) -> String {
        let proxy = config.proxies.first { $0.id == id } ?? config.proxies.first
        return proxy?.displayName ?? "no proxy"
    }

    // MARK: saving

    private func update(_ change: (inout AppConfig) -> Void) {
        change(&config)
        ConfigStore.shared.save(config)
        tunnel.configDidChange()
    }

    private static func upsert<T: Identifiable>(_ item: T, in items: inout [T]) {
        if let index = items.firstIndex(where: { $0.id == item.id }) {
            items[index] = item
        } else {
            items.append(item)
        }
    }
}

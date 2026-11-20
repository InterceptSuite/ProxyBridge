import Foundation
import Network

/// A UDP flow that leaves through a SOCKS5 proxy: a TCP control connection asks the proxy for a UDP relay,
/// then datagrams to any destination go through that relay.
final class ProxyUDPSession: UDPUpstream {
    var lastUsed = Date()

    private let proxy: ProxyConfig
    private let queue: DispatchQueue
    private let onReply: (Socks5.Datagram) -> Void
    private let onClose: () -> Void
    private var control: NWConnection?
    private var relay: NWConnection?
    private var pending: [Data] = []

    init(proxy: ProxyConfig, queue: DispatchQueue, onReply: @escaping (Socks5.Datagram) -> Void, onClose: @escaping () -> Void) {
        self.proxy = proxy
        self.queue = queue
        self.onReply = onReply
        self.onClose = onClose
        associate()
    }

    func send(host: String, port: Int, payload: Data) {
        guard let packet = Socks5.frame(host: host, port: port, payload: payload) else { return }
        if let relay {
            relay.send(content: packet, completion: .contentProcessed { _ in })
        } else {
            pending.append(packet)
        }
    }

    func cancel() {
        control?.cancel()
        relay?.cancel()
        control = nil
        relay = nil
    }

    private func associate() {
        let control = NWConnection(to: proxy.endpoint, using: .tcp)
        self.control = control
        control.open(on: queue) { [weak self] ready in
            guard let self, ready else { return self?.close() ?? () }
            Socks5.negotiate(control, proxy: self.proxy) { result in
                guard case .success = result else { return self.close() }
                Socks5.request(control, command: .udpAssociate, host: "0.0.0.0", port: 0) { result in
                    guard case .success(let bound) = result else { return self.close() }
                    self.openRelay(host: bound.host, port: bound.port)
                    self.watchControl()
                }
            }
        }
    }

    private func openRelay(host: String, port: Int) {
        // some proxies answer with 0.0.0.0, meaning "the address you reached me on"
        let target = (host == "0.0.0.0" || host.isEmpty) ? proxy.host : host
        let relay = NWConnection(to: .hostPort(target, port), using: .udp)
        self.relay = relay
        relay.start(queue: queue)
        pending.forEach { relay.send(content: $0, completion: .contentProcessed { _ in }) }
        pending.removeAll()
        receiveReplies(on: relay)
    }

    /// The association ends when the control connection closes.
    private func watchControl() {
        control?.receive(minimumIncompleteLength: 1, maximumLength: 1) { [weak self] _, _, isComplete, error in
            if isComplete || error != nil {
                self?.close()
            } else {
                self?.watchControl()
            }
        }
    }

    private func receiveReplies(on relay: NWConnection) {
        relay.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, let datagram = Socks5.parseDatagram([UInt8](data)) { self.onReply(datagram) }
            if error == nil { self.receiveReplies(on: relay) }
        }
    }

    private func close() {
        cancel()
        onClose()
    }
}

import Foundation
import Network
import os

/// A SOCKS5 server on the loopback interface inside the extension. hev turns every connection and UDP flow of
/// the device into a request to this server, which makes it the one place where the rules are applied.
final class LocalSocks5Server {
    private let queue = DispatchQueue(label: "com.interceptsuite.proxybridge.router")
    private let log = TunnelLogger(category: "router")
    private let lock = NSLock()
    private var engine = RuleEngine(config: AppConfig())
    private var listener: NWListener?
    private var udp: UDPRelay?

    /// Where DNS queries are forwarded to. Set before the tunnel starts.
    var dnsUpstreams: [String] = []

    func update(_ config: AppConfig) {
        lock.lock()
        engine = RuleEngine(config: config)
        lock.unlock()
    }

    func route(ip: String, port: Int, isUDP: Bool) -> Route {
        let flow = FlowInfo(ip: ip, port: port, isUDP: isUDP, domains: DNSMapStore.shared.domains(forIP: ip))
        lock.lock()
        let engine = self.engine
        lock.unlock()
        return engine.route(for: flow)
    }

    /// Calls back with the TCP port to point hev at, once both the TCP and the UDP side are listening.
    func start(ready: @escaping (Result<UInt16, Error>) -> Void) {
        let udp = UDPRelay(server: self, queue: queue)
        self.udp = udp
        udp.start { [weak self] error in
            if let error { return ready(.failure(error)) }
            self?.listen(ready: ready)
        }
    }

    func stop() {
        listener?.cancel()
        udp?.stop()
        listener = nil
        udp = nil
    }

    private func listen(ready: @escaping (Result<UInt16, Error>) -> Void) {
        let listener: NWListener
        do {
            listener = try NWListener(using: NWParameters.tcp.listeningOnLoopback())
        } catch {
            return ready(.failure(error))
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return connection.cancel() }
            connection.start(queue: self.queue)
            self.greet(connection)
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                ready(.success(listener.port?.rawValue ?? 0))
            case .failed(let error):
                ready(.failure(error))
            default:
                break
            }
        }
        self.listener = listener
        listener.start(queue: queue)
    }

    // MARK: SOCKS5 handshake with hev, which is on loopback and needs no authentication

    private func greet(_ connection: NWConnection) {
        connection.read(2) { head in
            guard let head, head[0] == Socks5.version else { return connection.cancel() }
            connection.read(Int(head[1])) { methods in
                guard methods != nil else { return connection.cancel() }
                connection.write([Socks5.version, 0]) { self.readRequest(connection) }
            }
        }
    }

    private func readRequest(_ connection: NWConnection) {
        connection.read(4) { head in
            guard let head, head[0] == Socks5.version else { return connection.cancel() }
            connection.readAddress(type: head[3]) { target in
                guard let target else { return connection.cancel() }
                switch Socks5.Command(rawValue: head[1]) {
                case .connect:
                    self.connect(connection, to: target)
                case .udpAssociate:
                    self.udp?.associate(connection)
                case nil:
                    self.refuse(connection, .commandNotSupported)
                }
            }
        }
    }

    private func connect(_ connection: NWConnection, to target: Socks5.Endpoint) {
        switch route(ip: target.host, port: target.port, isUDP: false) {
        case .block:
            refuse(connection, .notAllowed)
        case .direct:
            let upstream = NWConnection(to: .hostPort(target.host, target.port), using: .tcp)
            upstream.open(on: queue) { ready in
                if !ready { self.log.error("direct connection failed") }
                ready ? self.relay(connection, upstream) : self.refuse(connection, .failure)
            }
        case .proxy(let proxy):
            let destination = proxy.sendHostname ? DNSMapStore.shared.hostname(forIP: target.host) ?? target.host : target.host
            ProxyClient.connect(to: destination, port: target.port, via: proxy, queue: queue) { result in
                switch result {
                case .success(let upstream): self.relay(connection, upstream)
                case .failure(let error):
                    self.log.error("proxy connection failed: \(String(describing: error))")
                    self.refuse(connection, .failure)
                }
            }
        }
    }

    private func relay(_ connection: NWConnection, _ upstream: NWConnection) {
        connection.write(Socks5.reply(.succeeded))
        Relay.pipe(connection, upstream)
    }

    private func refuse(_ connection: NWConnection, _ reason: Socks5.Reply) {
        connection.write(Socks5.reply(reason)) { connection.cancel() }
    }
}

import Foundation
import Network
import os

/// A way out for datagrams of one UDP flow.
protocol UDPUpstream: AnyObject {
    var lastUsed: Date { get set }
    func send(host: String, port: Int, payload: Data)
    func cancel()
}

/// Receives the datagrams hev wraps in SOCKS5 UDP framing, applies the rules and sends each one direct or
/// through a proxy. Replies go back to hev in the same framing. DNS is always answered here so the
/// names can be remembered for domain rules.
///
/// Everything runs on `queue`, so the session table needs no lock.
final class UDPRelay {
    private struct SessionKey: Hashable {
        let source: ObjectIdentifier
        let target: String
    }

    private static let idleLimit: TimeInterval = 60
    private static let dnsTimeout: TimeInterval = 2

    private unowned let server: LocalSocks5Server
    private let queue: DispatchQueue
    private var listener: NWListener?
    private var sweeper: DispatchSourceTimer?
    private var sessions: [SessionKey: UDPUpstream] = [:]
    private var warnedProxies: Set<UUID> = []
    private let log = TunnelLogger(category: "udp")
    private(set) var port: UInt16 = 0

    init(server: LocalSocks5Server, queue: DispatchQueue) {
        self.server = server
        self.queue = queue
    }

    func start(ready: @escaping (Error?) -> Void) {
        let listener: NWListener
        do {
            listener = try NWListener(using: NWParameters.udp.listeningOnLoopback())
        } catch {
            return ready(error)
        }
        listener.newConnectionHandler = { [weak self] connection in
            connection.start(queue: self?.queue ?? .global())
            self?.receive(on: connection)
        }
        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.port = listener.port?.rawValue ?? 0
                ready(nil)
            case .failed(let error):
                ready(error)
            default:
                break
            }
        }
        self.listener = listener
        listener.start(queue: queue)

        let sweeper = DispatchSource.makeTimerSource(queue: queue)
        sweeper.schedule(deadline: .now() + 15, repeating: 15)
        sweeper.setEventHandler { [weak self] in self?.dropIdleSessions() }
        sweeper.resume()
        self.sweeper = sweeper
    }

    func stop() {
        listener?.cancel()
        sweeper?.cancel()
        queue.async {
            self.sessions.values.forEach { $0.cancel() }
            self.sessions.removeAll()
        }
        listener = nil
        sweeper = nil
    }

    /// Answers a UDP ASSOCIATE request with the address of this relay.
    func associate(_ control: NWConnection) {
        control.write([Socks5.version, Socks5.Reply.succeeded.rawValue, 0] + Socks5.encode(host: "::1", port: Int(port)))
        watch(control)
    }

    // MARK: datagrams from hev

    /// The association lasts as long as the control connection, hev closes it to end the flow.
    private func watch(_ control: NWConnection) {
        control.receive(minimumIncompleteLength: 1, maximumLength: 1) { [weak self] _, _, isComplete, error in
            if isComplete || error != nil {
                control.cancel()
            } else {
                self?.watch(control)
            }
        }
    }

    private func receive(on source: NWConnection) {
        source.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, let datagram = Socks5.parseDatagram([UInt8](data)) {
                self.handle(datagram, from: source)
            }
            if error == nil {
                self.receive(on: source)
            } else {
                source.cancel()
                self.dropSessions(of: source)
            }
        }
    }

    private func handle(_ datagram: Socks5.Datagram, from source: NWConnection) {
        if datagram.port == 53 {
            let servers = datagram.host == TunnelNetwork.dnsServer ? server.dnsUpstreams : [datagram.host]
            resolve(datagram, from: source, using: servers[...])
            return
        }

        let upstream: UDPUpstream
        switch server.route(ip: datagram.host, port: datagram.port, isUDP: true) {
        case .block:
            return
        case .proxy(let proxy) where proxy.kind == .socks5:
            upstream = session(for: source, target: proxy.id.uuidString) { key in
                ProxyUDPSession(proxy: proxy, queue: self.queue,
                                onReply: { self.reply($0, to: source) },
                                onClose: { self.sessions[key] = nil })
            }
        case .proxy(let proxy):
            warnOnce(about: proxy)
            upstream = directSession(for: datagram, from: source)
        case .direct:
            upstream = directSession(for: datagram, from: source)
        }
        upstream.lastUsed = Date()
        upstream.send(host: datagram.host, port: datagram.port, payload: datagram.payload)
    }

    private func directSession(for datagram: Socks5.Datagram, from source: NWConnection) -> UDPUpstream {
        session(for: source, target: "\(datagram.host):\(datagram.port)") { key in
            DirectUDPSession(host: datagram.host, port: datagram.port, queue: self.queue,
                             onReply: { self.reply($0, to: source) },
                             onClose: { self.sessions[key] = nil })
        }
    }

    /// An HTTP proxy cannot carry UDP, so that traffic goes direct. Say so once per proxy.
    private func warnOnce(about proxy: ProxyConfig) {
        guard warnedProxies.insert(proxy.id).inserted else { return }
        log.warning("UDP cannot go through an HTTP proxy, sending it direct")
    }

    private func session(for source: NWConnection, target: String, make: (SessionKey) -> UDPUpstream) -> UDPUpstream {
        let key = SessionKey(source: ObjectIdentifier(source), target: target)
        if let existing = sessions[key] { return existing }
        let created = make(key)
        sessions[key] = created
        return created
    }

    private func reply(_ datagram: Socks5.Datagram, to source: NWConnection) {
        guard let packet = Socks5.frame(host: datagram.host, port: datagram.port, payload: datagram.payload) else { return }
        source.send(content: packet, completion: .contentProcessed { _ in })
    }

    // MARK: DNS

    /// Asks the servers one after the other until one answers, and remembers the names in the answer.
    private func resolve(_ query: Socks5.Datagram, from source: NWConnection, using servers: ArraySlice<String>) {
        guard let address = servers.first else {
            log.error("no DNS server answered")
            return
        }
        let connection = NWConnection(to: .hostPort(address, 53), using: .udp)
        var finished = false
        let finish = { (answer: Data?) in
            guard !finished else { return }
            finished = true
            connection.cancel()
            guard let answer else { return self.resolve(query, from: source, using: servers.dropFirst()) }
            if let parsed = DNSParser.parse([UInt8](answer)) {
                DNSMapStore.shared.record(domain: parsed.domain, ips: parsed.ips)
            }
            self.reply(Socks5.Datagram(host: query.host, port: query.port, payload: answer), to: source)
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.send(content: query.payload, completion: .contentProcessed { _ in })
                connection.receiveMessage { data, _, _, _ in finish(data) }
            case .failed, .waiting:
                finish(nil)
            default:
                break
            }
        }
        queue.asyncAfter(deadline: .now() + Self.dnsTimeout) { finish(nil) }
        connection.start(queue: queue)
    }

    // MARK: cleanup

    private func dropIdleSessions() {
        let limit = Date().addingTimeInterval(-Self.idleLimit)
        for (key, session) in sessions where session.lastUsed < limit {
            session.cancel()
            sessions[key] = nil
        }
    }

    private func dropSessions(of source: NWConnection) {
        let id = ObjectIdentifier(source)
        for (key, session) in sessions where key.source == id {
            session.cancel()
            sessions[key] = nil
        }
    }
}

/// A UDP flow that leaves directly, from one local port per destination.
final class DirectUDPSession: UDPUpstream {
    var lastUsed = Date()

    private let connection: NWConnection
    private let host: String
    private let port: Int
    private let onReply: (Socks5.Datagram) -> Void
    private let onClose: () -> Void

    init(host: String, port: Int, queue: DispatchQueue, onReply: @escaping (Socks5.Datagram) -> Void, onClose: @escaping () -> Void) {
        self.host = host
        self.port = port
        self.onReply = onReply
        self.onClose = onClose
        connection = NWConnection(to: .hostPort(host, port), using: .udp)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled: self?.onClose()
            default: break
            }
        }
        connection.start(queue: queue)
        receive()
    }

    func send(host: String, port: Int, payload: Data) {
        connection.send(content: payload, completion: .contentProcessed { _ in })
    }

    func cancel() {
        connection.cancel()
    }

    private func receive() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data { self.onReply(Socks5.Datagram(host: self.host, port: self.port, payload: data)) }
            if error == nil { self.receive() }
        }
    }
}

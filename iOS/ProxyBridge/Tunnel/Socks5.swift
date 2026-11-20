import Foundation
import Network

/// SOCKS5 wire format, shared by the local server that hev talks to and the client that talks to the upstream proxy.
enum Socks5 {
    static let version: UInt8 = 5

    enum Command: UInt8 {
        case connect = 1
        case udpAssociate = 3
    }

    enum Reply: UInt8 {
        case succeeded = 0
        case failure = 1
        case notAllowed = 2
        case commandNotSupported = 7
    }

    enum AddressType: UInt8 {
        case ipv4 = 1
        case domain = 3
        case ipv6 = 4
    }

    enum Failure: Error {
        case handshake
        case authentication
        case rejected(UInt8)
    }

    typealias Endpoint = (host: String, port: Int)

    /// Address type, address and port. A host that is not an IP literal is sent as a domain name.
    static func encode(host: String, port: Int) -> [UInt8] {
        var bytes: [UInt8]
        if let ip = RuleMatch.ipToBytes(host) {
            bytes = [(ip.count == 4 ? AddressType.ipv4 : .ipv6).rawValue] + ip
        } else {
            let name = Array(host.utf8.prefix(255))
            bytes = [AddressType.domain.rawValue, UInt8(name.count)] + name
        }
        return bytes + [UInt8(port >> 8), UInt8(port & 0xFF)]
    }

    static func reply(_ code: Reply) -> [UInt8] {
        [version, code.rawValue, 0, AddressType.ipv4.rawValue, 0, 0, 0, 0, 0, 0]
    }

    // MARK: UDP datagrams

    struct Datagram {
        let host: String
        let port: Int
        let payload: Data
    }

    /// Frames a payload for the SOCKS5 UDP relay. Needs an IP literal because the receiver is the packet stack.
    static func frame(host: String, port: Int, payload: Data) -> Data? {
        guard RuleMatch.ipToBytes(host) != nil else { return nil }
        return Data([0, 0, 0] + encode(host: host, port: port)) + payload
    }

    /// Reads a SOCKS5 UDP datagram. Fragments and domain addresses are not supported.
    static func parseDatagram(_ bytes: [UInt8]) -> Datagram? {
        guard bytes.count > 4, bytes[2] == 0 else { return nil }
        let length: Int
        switch bytes[3] {
        case AddressType.ipv4.rawValue: length = 4
        case AddressType.ipv6.rawValue: length = 16
        default: return nil
        }
        let portIndex = 4 + length
        guard bytes.count >= portIndex + 2 else { return nil }
        return Datagram(host: RuleMatch.ipString(Array(bytes[4..<portIndex])),
                        port: Int(bytes[portIndex]) << 8 | Int(bytes[portIndex + 1]),
                        payload: Data(bytes[(portIndex + 2)...]))
    }

    // MARK: client side handshake

    /// Greeting and optional user name and password authentication.
    static func negotiate(_ connection: NWConnection, proxy: ProxyConfig, then: @escaping (Result<Void, Error>) -> Void) {
        let method: UInt8 = proxy.hasCredentials ? 2 : 0
        connection.write([version, 1, method]) {
            connection.read(2) { answer in
                guard let answer, answer[0] == version else { return then(.failure(Failure.handshake)) }
                switch answer[1] {
                case 0:
                    then(.success(()))
                case 2 where proxy.hasCredentials:
                    authenticate(connection, proxy: proxy, then: then)
                default:
                    then(.failure(Failure.handshake))
                }
            }
        }
    }

    private static func authenticate(_ connection: NWConnection, proxy: ProxyConfig, then: @escaping (Result<Void, Error>) -> Void) {
        let user = Array(proxy.username.utf8.prefix(255))
        let password = Array(proxy.password.utf8.prefix(255))
        let message = [1, UInt8(user.count)] + user + [UInt8(password.count)] + password
        connection.write(message) {
            connection.read(2) { answer in
                then(answer?[1] == 0 ? .success(()) : .failure(Failure.authentication))
            }
        }
    }

    /// Sends a request and reads the bound address of the reply.
    static func request(_ connection: NWConnection, command: Command, host: String, port: Int,
                        then: @escaping (Result<Endpoint, Error>) -> Void) {
        connection.write([version, command.rawValue, 0] + encode(host: host, port: port)) {
            connection.read(4) { head in
                guard let head, head[0] == version else { return then(.failure(Failure.handshake)) }
                guard head[1] == Reply.succeeded.rawValue else { return then(.failure(Failure.rejected(head[1]))) }
                connection.readAddress(type: head[3]) { bound in
                    then(bound.map { .success($0) } ?? .failure(Failure.handshake))
                }
            }
        }
    }
}

extension NWConnection {
    func write(_ bytes: [UInt8], then: @escaping () -> Void = {}) {
        send(content: Data(bytes), completion: .contentProcessed { _ in then() })
    }

    /// Reads exactly `count` bytes, nil if the connection ends first.
    func read(_ count: Int, then: @escaping ([UInt8]?) -> Void) {
        guard count > 0 else { return then([]) }
        receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
            guard error == nil, let data, data.count == count else { return then(nil) }
            then([UInt8](data))
        }
    }

    /// Reads a SOCKS5 address and port once the address type is known.
    func readAddress(type: UInt8, then: @escaping (Socks5.Endpoint?) -> Void) {
        func finish(_ bytes: [UInt8]?, host: (ArraySlice<UInt8>) -> String) {
            guard let bytes, bytes.count >= 2 else { return then(nil) }
            let split = bytes.count - 2
            then((host(bytes[..<split]), Int(bytes[split]) << 8 | Int(bytes[split + 1])))
        }
        switch type {
        case Socks5.AddressType.ipv4.rawValue:
            read(6) { finish($0) { RuleMatch.ipString(Array($0)) } }
        case Socks5.AddressType.ipv6.rawValue:
            read(18) { finish($0) { RuleMatch.ipString(Array($0)) } }
        case Socks5.AddressType.domain.rawValue:
            read(1) { length in
                guard let length = length?.first else { return then(nil) }
                self.read(Int(length) + 2) { finish($0) { String(decoding: $0, as: UTF8.self) } }
            }
        default:
            then(nil)
        }
    }

    /// Starts the connection and reports once it is ready. A connection that is still waiting for a path
    /// (refused, no route, no network) counts as failed so callers never hang.
    func open(on queue: DispatchQueue, timeout: TimeInterval = 10, then: @escaping (Bool) -> Void) {
        var finished = false
        let finish = { (success: Bool) in
            guard !finished else { return }
            finished = true
            if !success { self.cancel() }
            then(success)
        }
        stateUpdateHandler = { state in
            switch state {
            case .ready: finish(true)
            case .failed, .waiting, .cancelled: finish(false)
            default: break
            }
        }
        queue.asyncAfter(deadline: .now() + timeout) { finish(false) }
        start(queue: queue)
    }
}

extension NWParameters {
    /// For a listener that is only reachable on the IPv6 loopback address. hev turns an IPv4 server address into a
    /// mapped IPv6 one, and that connection fails on iOS, so its documented iOS setup uses ::1.
    func listeningOnLoopback() -> NWParameters {
        requiredInterfaceType = .loopback
        requiredLocalEndpoint = .hostPort(host: "::1", port: .any)
        return self
    }
}

extension NWEndpoint {
    static func hostPort(_ host: String, _ port: Int) -> NWEndpoint {
        .hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
    }
}

extension ProxyConfig {
    var endpoint: NWEndpoint { .hostPort(host, port) }
}

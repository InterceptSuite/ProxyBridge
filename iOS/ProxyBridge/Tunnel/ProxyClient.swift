import Foundation
import Network

/// Opens a TCP connection to a host through a SOCKS5 or HTTP CONNECT proxy.
enum ProxyClient {
    static func connect(to host: String, port: Int, via proxy: ProxyConfig, queue: DispatchQueue,
                        completion: @escaping (Result<NWConnection, Error>) -> Void) {
        let connection = NWConnection(to: proxy.endpoint, using: .tcp)
        connection.open(on: queue) { ready in
            guard ready else { return completion(.failure(Socks5.Failure.handshake)) }
            switch proxy.kind {
            case .socks5:
                socks5(connection, host: host, port: port, proxy: proxy, completion: completion)
            case .http:
                httpConnect(connection, host: host, port: port, proxy: proxy, completion: completion)
            }
        }
    }

    private static func socks5(_ connection: NWConnection, host: String, port: Int, proxy: ProxyConfig,
                               completion: @escaping (Result<NWConnection, Error>) -> Void) {
        Socks5.negotiate(connection, proxy: proxy) { result in
            if case .failure(let error) = result { return fail(connection, error, completion) }
            Socks5.request(connection, command: .connect, host: host, port: port) { result in
                switch result {
                case .success: completion(.success(connection))
                case .failure(let error): fail(connection, error, completion)
                }
            }
        }
    }

    private static func httpConnect(_ connection: NWConnection, host: String, port: Int, proxy: ProxyConfig,
                                    completion: @escaping (Result<NWConnection, Error>) -> Void) {
        var request = "CONNECT \(host):\(port) HTTP/1.1\r\nHost: \(host):\(port)\r\n"
        if proxy.hasCredentials {
            let token = Data("\(proxy.username):\(proxy.password)".utf8).base64EncodedString()
            request += "Proxy-Authorization: Basic \(token)\r\n"
        }
        request += "\r\n"

        connection.write(Array(request.utf8)) {
            readHeaders(connection, received: []) { headers in
                let status = headers.flatMap { String(decoding: $0, as: UTF8.self).split(separator: " ").dropFirst().first }
                if status == "200" {
                    completion(.success(connection))
                } else {
                    fail(connection, Socks5.Failure.rejected(0), completion)
                }
            }
        }
    }

    /// Reads one byte at a time up to the blank line, so no tunnelled data is consumed by accident.
    private static func readHeaders(_ connection: NWConnection, received: [UInt8], then: @escaping ([UInt8]?) -> Void) {
        connection.read(1) { byte in
            guard let byte else { return then(nil) }
            let data = received + byte
            if data.suffix(4) == [13, 10, 13, 10] {
                then(data)
            } else if data.count > 8192 {
                then(nil)
            } else {
                readHeaders(connection, received: data, then: then)
            }
        }
    }

    private static func fail(_ connection: NWConnection, _ error: Error, _ completion: (Result<NWConnection, Error>) -> Void) {
        connection.cancel()
        completion(.failure(error))
    }
}

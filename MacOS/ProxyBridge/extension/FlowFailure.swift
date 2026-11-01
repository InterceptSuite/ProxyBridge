import NetworkExtension

// The error a connection is closed with when it could not be set up: the proxy is down, or it said no.
//
// An application's connect() only fails when the flow is closed with an error. A flow closed with no
// error looks like a connection that opened and then ended, so the application sends its data into it
// and gets a reset. A browser that raced IPv6 against IPv4 has already picked the IPv6 attempt as the
// winner by then, so the IPv4 attempt never finishes and the page fails (issue #276). With a real error
// the attempt fails during connect and the application can try its next address.
//
// Use nil (a clean close) only for the normal end of a connection that worked.
enum FlowFailure {
    static func make(_ code: NEAppProxyFlowError.Code) -> NSError {
        NSError(domain: NEAppProxyFlowError.errorDomain, code: code.rawValue, userInfo: nil)
    }

    // the proxy could not be reached, or did not answer like a proxy
    static var proxyUnreachable: NSError { make(.hostUnreachable) }
    // the proxy or the settings refused the connection (bad credentials, unsupported request)
    static var refused: NSError { make(.refused) }
    // nothing finished in time
    static var timedOut: NSError { make(.timedOut) }

    // the REP byte of a SOCKS5 reply (RFC 1928)
    static func socks(_ rep: UInt8) -> NSError {
        switch rep {
        case 0x02, 0x05, 0x07, 0x08:    // not allowed, connection refused, command or address type not supported
            return make(.refused)
        case 0x06:                      // TTL expired
            return make(.timedOut)
        default:                        // 0x01 general failure, 0x03 network and 0x04 host unreachable, unknown
            return make(.hostUnreachable)
        }
    }

    // the status code of an HTTP proxy's answer to CONNECT, nil when there was no usable status line
    static func http(_ status: Int?) -> NSError {
        guard let status = status else { return make(.hostUnreachable) }
        switch status {
        case 408, 504:
            return make(.timedOut)
        case 502, 503:
            return make(.hostUnreachable)
        case 400..<500:                 // 403 forbidden, 407 authentication required, ...
            return make(.refused)
        default:
            return make(.hostUnreachable)
        }
    }
}

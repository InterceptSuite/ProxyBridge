import Foundation
import NetworkExtension

// FlowFailure turns a proxy failure into the error a connection is closed with. The point of the whole
// type: a connection that could not be set up must fail the application's connect (issue #276), so every
// result here has to be a real error in the flow error domain, never nil.
var fails = 0
func t(_ name: String, _ ok: Bool) { if !ok { fails += 1; print("FAIL \(name)") } }

func code(_ e: NSError) -> Int { e.code }
let domain = NEAppProxyFlowError.errorDomain
let hostUnreachable = NEAppProxyFlowError.Code.hostUnreachable.rawValue
let refused = NEAppProxyFlowError.Code.refused.rawValue
let timedOut = NEAppProxyFlowError.Code.timedOut.rawValue

t("proxy unreachable is a host unreachable error", code(FlowFailure.proxyUnreachable) == hostUnreachable)
t("refused is a refused error", code(FlowFailure.refused) == refused)
t("timed out is a timed out error", code(FlowFailure.timedOut) == timedOut)
t("errors are in the flow error domain", FlowFailure.proxyUnreachable.domain == domain && FlowFailure.refused.domain == domain && FlowFailure.timedOut.domain == domain)

// SOCKS5 REP codes (RFC 1928)
t("REP 01 general failure", code(FlowFailure.socks(0x01)) == hostUnreachable)
t("REP 02 not allowed", code(FlowFailure.socks(0x02)) == refused)
t("REP 03 network unreachable", code(FlowFailure.socks(0x03)) == hostUnreachable)
t("REP 04 host unreachable", code(FlowFailure.socks(0x04)) == hostUnreachable)
t("REP 05 connection refused", code(FlowFailure.socks(0x05)) == refused)
t("REP 06 TTL expired", code(FlowFailure.socks(0x06)) == timedOut)
t("REP 07 command not supported", code(FlowFailure.socks(0x07)) == refused)
t("REP 08 address type not supported", code(FlowFailure.socks(0x08)) == refused)
t("an unknown REP is still a failure", code(FlowFailure.socks(0x7f)) == hostUnreachable && code(FlowFailure.socks(0xff)) == hostUnreachable)
t("every REP value gives a flow domain error", (0...255).allSatisfy { FlowFailure.socks(UInt8($0)).domain == domain })

// HTTP CONNECT status codes
t("HTTP 502 bad gateway", code(FlowFailure.http(502)) == hostUnreachable)
t("HTTP 503 unavailable", code(FlowFailure.http(503)) == hostUnreachable)
t("HTTP 504 gateway timeout", code(FlowFailure.http(504)) == timedOut)
t("HTTP 408 request timeout", code(FlowFailure.http(408)) == timedOut)
t("HTTP 403 forbidden", code(FlowFailure.http(403)) == refused)
t("HTTP 407 authentication required", code(FlowFailure.http(407)) == refused)
t("HTTP 404 and other 4xx are refused", code(FlowFailure.http(404)) == refused && code(FlowFailure.http(429)) == refused)
t("HTTP 500 and unknown codes are host unreachable", code(FlowFailure.http(500)) == hostUnreachable && code(FlowFailure.http(700)) == hostUnreachable)
t("no status line is host unreachable", code(FlowFailure.http(nil)) == hostUnreachable)
t("every HTTP status gives a flow domain error", (0...999).allSatisfy { FlowFailure.http($0).domain == domain } && FlowFailure.http(nil).domain == domain)

print(fails == 0 ? "flow failure tests: ALL PASS" : "flow failure tests: \(fails) FAILED")
exit(fails == 0 ? 0 : 1)

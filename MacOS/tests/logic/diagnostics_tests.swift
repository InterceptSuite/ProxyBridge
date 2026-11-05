import Foundation
import NetworkExtension

// ProviderDiagnostics.text turns an NEProviderStopReason into words for the log. A reason this build does
// not know must still print its number, never an empty string.
var fails = 0
func t(_ name: String, _ ok: Bool) { if !ok { fails += 1; print("FAIL \(name)") } }

t("user initiated", ProviderDiagnostics.text(for: .userInitiated) == "stopped by the user (1)")
t("provider failed", ProviderDiagnostics.text(for: .providerFailed) == "the provider failed (2)")
t("configuration removed", ProviderDiagnostics.text(for: .configurationRemoved) == "the configuration was removed (10)")
t("superceded", ProviderDiagnostics.text(for: .superceded) == "replaced by another configuration (11)")
t("none", ProviderDiagnostics.text(for: .none) == "none (0)")
t("every known reason has words", (0...17).allSatisfy { n in
    guard let r = NEProviderStopReason(rawValue: n) else { return false }
    let s = ProviderDiagnostics.text(for: r)
    return !s.hasPrefix("unknown") && s.hasSuffix("(\(n))")
})
t("an unknown reason prints its number", ProviderDiagnostics.text(for: NEProviderStopReason(rawValue: 99)!) == "unknown reason (99)")

print(fails == 0 ? "diagnostics tests: ALL PASS" : "diagnostics tests: \(fails) FAILED")
exit(fails == 0 ? 0 : 1)

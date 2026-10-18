import Foundation

enum CLIText {
    // text that comes from outside (profile names, DNS names, a proxy's error reply, process names)
    // is printed to a terminal. control characters, including the escape that starts terminal
    // escape sequences, are replaced so such text can't rewrite what the user sees
    static func safe(_ text: String) -> String {
        var out = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            if scalar.value < 0x20 || (0x7F...0x9F).contains(scalar.value) { out.append("?") } else { out.append(scalar) }
        }
        return String(out)
    }

    // for messages that are built with line breaks on purpose: each line is made safe,
    // the breaks stay (parts that came from outside are made safe before they are joined)
    static func lines(_ text: String) -> String {
        text.split(separator: "\n", omittingEmptySubsequences: false).map { safe(String($0)) }.joined(separator: "\n")
    }
}

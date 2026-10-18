import Foundation

// command line options. the app is one executable: no options means the GUI, any
// of these options means the command line mode (see main.swift)
struct CLIOptions: Equatable {
    var help = false
    var version = false
    var update = false
    var listProfiles = false
    var profile: String?    // a saved profile name, or "-" for standard input
    var verbose = 0         // 0 silent, 1 log messages, 2 connections, 3 both
}

enum CLIParseResult: Equatable {
    case run(CLIOptions)
    case failure(String)
}

enum CLIArguments {
    static let triggers: Set<String> = ["--cli", "--profile", "--verbose", "--version", "--update", "--list-profiles", "--help", "-h", "-?"]

    // true when the process was started for the command line. a normal launch from
    // Finder or the Dock passes none of these, so it stays the GUI
    static func isCLI(_ args: [String]) -> Bool {
        return args.dropFirst().contains { arg in
            triggers.contains(arg) || arg.hasPrefix("--profile=") || arg.hasPrefix("--verbose=")
        }
    }

    static func parse(_ args: [String]) -> CLIParseResult {
        var o = CLIOptions()
        var i = 1
        while i < args.count {
            var arg = args[i]
            var inline: String?
            if arg.hasPrefix("--"), let eq = arg.firstIndex(of: "=") {
                inline = String(arg[arg.index(after: eq)...])
                arg = String(arg[..<eq])
            }
            switch arg {
            case "--cli": break
            case "--help", "-h", "-?": o.help = true
            case "--version": o.version = true
            case "--update": o.update = true
            case "--list-profiles": o.listProfiles = true
            case "--profile", "--verbose":
                let value: String
                if let inline = inline {
                    value = inline
                } else if i + 1 < args.count, !(args[i + 1].hasPrefix("--")) {
                    i += 1
                    value = args[i]
                } else {
                    return .failure("\(arg) requires a value. Use --help.")
                }
                if arg == "--profile" {
                    guard !value.isEmpty else { return .failure("--profile requires a profile name, or - to read from standard input.") }
                    o.profile = value
                } else {
                    guard let level = Int(value), (0...3).contains(level) else { return .failure("--verbose level must be 0-3.") }
                    o.verbose = level
                }
            default:
                return .failure("Unknown option '\(args[i])'. Use --help.")
            }
            i += 1
        }
        // running needs a profile, the other options stand on their own
        if !(o.help || o.version || o.update || o.listProfiles) && o.profile == nil {
            return .failure("--profile is required. Use --help.")
        }
        return .run(o)
    }

    static let usage = """
    ProxyBridge CLI - run a ProxyBridge profile without the window.

    USAGE:
      proxybridge --profile <name | -> [options]

    OPTIONS:
      --profile <name>   Run a profile saved in the ProxyBridge app (see --list-profiles)
      --profile -        Read a profile (.pbprofile, exported from the app) from standard input
      --list-profiles    List the saved profiles and exit
      --verbose <0-3>    Logging: 0 silent (default), 1 log messages, 2 connections, 3 both
      --update           Check for updates
      --version          Show the version
      -h, --help         Show this help

    EXAMPLES:
      proxybridge --list-profiles
      proxybridge --profile Default --verbose 2
      cat ~/work.pbprofile | proxybridge --profile - --verbose 3

    NOTES:
      - Press Ctrl+C to stop. The rules are cleared and the tunnel is stopped.
      - The system extension has to be approved once (System Settings > Privacy & Security).
        The first run waits for that approval.
      - Quit the ProxyBridge app first: only one of them can control the extension.
      - The app is sandboxed, so a file path cannot be read. Use a saved profile name,
        or pipe the file in with --profile -
    """
}

import SwiftUI

// one executable, two modes. started with a command line option (--profile, --version, ...)
// it runs without a window (CLIRunner.swift). started normally, from Finder or the Dock,
// it is the app.
if CLIArguments.isCLI(CommandLine.arguments) {
    CLI.run(arguments: CommandLine.arguments)
} else {
    ProxyBridgeGUIApp.main()
}

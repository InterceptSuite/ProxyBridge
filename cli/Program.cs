using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Runtime.Versioning;

namespace ProxyBridge.CLI;

class Program
{
    private static ProxyBridgeNative.LogCallback? _logCallback;
    private static ProxyBridgeNative.ConnectionCallback? _connectionCallback;
    private static bool _isRunning = false;

    static int Main(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
        {
            ShowHelp();
            return 0;
        }

        if (!IsRunningAsAdministrator())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\nERROR: ProxyBridge requires Administrator privileges!");
            Console.ResetColor();
            Console.WriteLine("Please run this application as Administrator.\n");
            return 1;
        }

        try
        {
            ShowBanner();

            var proxyConfig = ParseProxyConfig(args);
            var rules = ParseRules(args);

            _logCallback = OnLog;
            _connectionCallback = OnConnection;

            ProxyBridgeNative.ProxyBridge_SetLogCallback(_logCallback);
            ProxyBridgeNative.ProxyBridge_SetConnectionCallback(_connectionCallback);

            Console.WriteLine($"Proxy: {proxyConfig.Type}://{proxyConfig.Ip}:{proxyConfig.Port}");

            if (!ProxyBridgeNative.ProxyBridge_SetProxyConfig(proxyConfig.Type, proxyConfig.Ip, proxyConfig.Port))
            {
                Console.WriteLine("ERROR: Failed to set proxy configuration");
                return 1;
            }

            if (rules.Count > 0)
            {
                Console.WriteLine($"Rules: {rules.Count}");
                foreach (var rule in rules)
                {
                    var ruleId = ProxyBridgeNative.ProxyBridge_AddRule(rule.ProcessName, rule.Action);
                    if (ruleId > 0)
                    {
                        Console.WriteLine($"  [{ruleId}] {rule.ProcessName} -> {rule.Action}");
                    }
                    else
                    {
                        Console.WriteLine($"  ERROR: Failed to add rule for {rule.ProcessName}");
                    }
                }
            }

            if (!ProxyBridgeNative.ProxyBridge_Start())
            {
                Console.WriteLine("ERROR: Failed to start ProxyBridge");
                return 1;
            }

            _isRunning = true;
            Console.WriteLine("\nProxyBridge started. Press Ctrl+C to stop...\n");

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Console.WriteLine("\n\nStopping ProxyBridge...");
                if (_isRunning)
                {
                    ProxyBridgeNative.ProxyBridge_Stop();
                    _isRunning = false;
                }
                Console.WriteLine("ProxyBridge stopped.");
            };

            while (_isRunning)
            {
                Thread.Sleep(100);
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: {ex.Message}");
            return 1;
        }
    }

    private static void OnLog(string message)
    {
        Console.WriteLine($"[LOG] {message}");
    }

    private static void OnConnection(string processName, uint pid, string destIp, ushort destPort, string proxyInfo)
    {
        Console.WriteLine($"[CONN] {processName} (PID:{pid}) -> {destIp}:{destPort} via {proxyInfo}");
    }

    private static (ProxyBridgeNative.ProxyType Type, string Ip, ushort Port) ParseProxyConfig(string[] args)
    {
        var proxyArg = GetArgValue(args, "--proxy");

        if (string.IsNullOrEmpty(proxyArg))
        {
            return (ProxyBridgeNative.ProxyType.SOCKS5, "127.0.0.1", 4444);
        }

        var socks5Match = Regex.Match(proxyArg, @"^socks5://([^:]+):(\d+)$", RegexOptions.IgnoreCase);
        if (socks5Match.Success)
        {
            return (
                ProxyBridgeNative.ProxyType.SOCKS5,
                socks5Match.Groups[1].Value,
                ushort.Parse(socks5Match.Groups[2].Value)
            );
        }

        var httpMatch = Regex.Match(proxyArg, @"^http://([^:]+):(\d+)$", RegexOptions.IgnoreCase);
        if (httpMatch.Success)
        {
            return (
                ProxyBridgeNative.ProxyType.HTTP,
                httpMatch.Groups[1].Value,
                ushort.Parse(httpMatch.Groups[2].Value)
            );
        }

        throw new ArgumentException($"Invalid proxy format: {proxyArg}. Use socks5://ip:port or http://ip:port");
    }

    private static List<(string ProcessName, ProxyBridgeNative.RuleAction Action)> ParseRules(string[] args)
    {
        var rules = new List<(string, ProxyBridgeNative.RuleAction)>();
        var ruleArg = GetArgValue(args, "--rule");

        if (string.IsNullOrEmpty(ruleArg))
        {
            return rules;
        }

        var rulePairs = ruleArg.Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in rulePairs)
        {
            var parts = pair.Split('=', 2);
            if (parts.Length != 2)
            {
                throw new ArgumentException($"Invalid rule format: {pair}. Use process=action");
            }

            var processName = parts[0].Trim();
            var actionStr = parts[1].Trim().ToUpper();

            var action = actionStr switch
            {
                "PROXY" => ProxyBridgeNative.RuleAction.PROXY,
                "DIRECT" => ProxyBridgeNative.RuleAction.DIRECT,
                "BLOCK" => ProxyBridgeNative.RuleAction.BLOCK,
                _ => throw new ArgumentException($"Invalid action: {actionStr}. Use PROXY, DIRECT, or BLOCK")
            };

            rules.Add((processName, action));
        }

        return rules;
    }

    private static string? GetArgValue(string[] args, string argName)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(argName, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }
        return null;
    }

    [SupportedOSPlatform("windows")]
    private static bool IsRunningAsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void ShowBanner()
    {
        Console.WriteLine();
        Console.WriteLine("  ____                        ____       _     _            ");
        Console.WriteLine(" |  _ \\ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___ ");
        Console.WriteLine(" | |_) | '__/ _ \\ \\/ / | | | |  _ \\| '__| |/ _` |/ _` |/ _ \\");
        Console.WriteLine(" |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/");
        Console.WriteLine(" |_|   |_|  \\___/_/\\_\\\\__, | |____/|_|  |_|\\__,_|\\__, |\\___|");
        Console.WriteLine("                      |___/                      |___/  V2.0");
        Console.WriteLine();
        Console.WriteLine("  Universal proxy client for Windows applications");
        Console.WriteLine();
        Console.WriteLine("\tAuthor: Sourav Kalal/InterceptSuite");
        Console.WriteLine("\tGitHub: https://github.com/InterceptSuite/ProxyBridge");
        Console.WriteLine();
    }

    private static void ShowHelp()
    {
        ShowBanner();
        Console.WriteLine(@"A lightweight proxy bridge for process-based traffic routing

USAGE:
    ProxyBridge_CLI [OPTIONS]

OPTIONS:
    --proxy <url>       Proxy server URL
                        Format: socks5://ip:port or http://ip:port
                        Default: socks5://127.0.0.1:4444

    --rule <rules>      Traffic routing rules (semicolon-separated)
                        Format: process=action;process=action
                        Actions: PROXY, DIRECT, BLOCK
                        Example: --rule ""chrome.exe=proxy;firefox.exe=direct;*=block""

    --help, -h          Show this help message

EXAMPLES:
    Start with default SOCKS5 proxy:
        ProxyBridge_CLI

    Use custom HTTP proxy:
        ProxyBridge_CLI --proxy http://192.168.1.100:8080

    Route specific processes:
        ProxyBridge_CLI --proxy socks5://127.0.0.1:1080 --rule ""chrome.exe=proxy;*=direct""

    Block all traffic except specific apps:
        ProxyBridge_CLI --rule ""chrome.exe=proxy;firefox.exe=proxy;*=block""

NOTES:
    - Press Ctrl+C to stop ProxyBridge
    - Use * as process name to match all traffic
    - Process names are case-insensitive
");
    }
}

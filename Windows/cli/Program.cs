using System.CommandLine;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text.Json.Serialization;

namespace ProxyBridge.CLI;

public class ProxyRuleImport
{
    public string ProcessNames { get; set; } = string.Empty;
    public string TargetHosts { get; set; } = string.Empty;
    public string TargetPorts { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
}

// JSON Source Generator for NativeAOT compatibility
[JsonSerializable(typeof(List<ProxyRuleImport>))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
public partial class ProxyRuleJsonContext : JsonSerializerContext
{
}

class Program
{
    private static ProxyBridgeNative.LogCallback? _logCallback;
    private static ProxyBridgeNative.ConnectionCallback? _connectionCallback;
    private static bool _isRunning = false;
    private static int _verboseLevel = 0;

    static async Task<int> Main(string[] args)
    {
        var proxyOption = new Option<string>(
            name: "--proxy",
            description: "Proxy server URL with optional authentication\n" +
                        "Format: type://ip:port or type://ip:port:username:password\n" +
                        "Examples: socks5://127.0.0.1:1080\n" +
                        "          http://proxy.com:8080:myuser:mypass",
            getDefaultValue: () => "socks5://127.0.0.1:4444");

        var ruleOption = new Option<string[]>(
            name: "--rule",
            description: "Traffic routing rule (multiple values supported, can repeat)\n" +
                        "Format: process:hosts:ports:protocol:action\n" +
                        "  process  - Process name(s): chrome.exe, chr*.exe, *.exe, or * (use ; for multiple: chrome.exe;firefox.exe)\n" +
                        "  hosts    - IP/host(s): *, google.com, 192.168.*.*, or multiple separated by ; or ,\n" +
                        "  ports    - Port(s): *, 443, 80;8080, 80-100, or multiple separated by ; or ,\n" +
                        "  protocol - TCP, UDP, or BOTH\n" +
                        "  action   - PROXY, DIRECT, or BLOCK\n" +
                        "Examples:\n" +
                        "  chrome.exe:*:*:TCP:PROXY\n" +
                        "  chrome.exe;firefox.exe:*:*:TCP:PROXY\n" +
                        "  *:*:53:UDP:PROXY\n" +
                        "  firefox.exe:*:80;443:TCP:DIRECT")
        {
            AllowMultipleArgumentsPerToken = false,
            Arity = ArgumentArity.ZeroOrMore
        };

        var ruleFileOption = new Option<string?>(
            name: "--rule-file",
            description: "Path to JSON file containing proxy rules\n" +
                        "JSON format (same as GUI export):\n" +
                        "[{\n" +
                        "  \"processNames\": \"chrome.exe\",\n" +
                        "  \"targetHosts\": \"*\",\n" +
                        "  \"targetPorts\": \"*\",\n" +
                        "  \"protocol\": \"TCP\",\n" +
                        "  \"action\": \"PROXY\",\n" +
                        "  \"enabled\": true\n" +
                        "}]\n" +
                        "Example: --rule-file C:\\\\rules.json",
            getDefaultValue: () => null);

        var dnsViaProxyOption = new Option<bool>(
            name: "--dns-via-proxy",
            description: "Route DNS queries through proxy (default: true)",
            getDefaultValue: () => true);

        var verboseOption = new Option<int>(
            name: "--verbose",
            description: "Logging verbosity level\n" +
                        "  0 - No logs (default)\n" +
                        "  1 - Show log messages only\n" +
                        "  2 - Show connection events only\n" +
                        "  3 - Show both logs and connections",
            getDefaultValue: () => 0);

        var updateCommand = new Command("--update", "Check for updates and download latest version from GitHub");

        var rootCommand = new RootCommand("ProxyBridge - Universal proxy client for Windows applications")
        {
            proxyOption,
            ruleOption,
            ruleFileOption,
            dnsViaProxyOption,
            verboseOption
        };

        rootCommand.AddCommand(updateCommand);

        updateCommand.SetHandler(async () =>
        {
            await CheckAndUpdate();
        });

        rootCommand.SetHandler(async (proxyUrl, rules, ruleFile, dnsViaProxy, verbose) =>
        {
            await RunProxyBridge(proxyUrl, rules, ruleFile, dnsViaProxy, verbose);
        }, proxyOption, ruleOption, ruleFileOption, dnsViaProxyOption, verboseOption);

        if (args.Contains("--help") || args.Contains("-h") || args.Contains("-?"))
        {
            ShowBanner();
        }

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task<int> RunProxyBridge(string proxyUrl, string[] rules, string? ruleFile, bool dnsViaProxy, int verboseLevel)
    {
        _verboseLevel = verboseLevel;
        ShowBanner();

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
            var proxyInfo = ParseProxyConfig(proxyUrl);
            var parsedRules = ParseRules(rules);

            if (!string.IsNullOrEmpty(ruleFile))
            {
                var fileRules = await LoadRulesFromFile(ruleFile);
                parsedRules.AddRange(fileRules);
            }

            _logCallback = OnLog;
            _connectionCallback = OnConnection;

            ProxyBridgeNative.ProxyBridge_SetLogCallback(_logCallback);
            ProxyBridgeNative.ProxyBridge_SetConnectionCallback(_connectionCallback);

            Console.WriteLine($"Proxy: {proxyInfo.Type}://{proxyInfo.Host}:{proxyInfo.Port}");
            if (!string.IsNullOrEmpty(proxyInfo.Username))
            {
                Console.WriteLine($"Proxy Auth: {proxyInfo.Username}:***");
            }
            Console.WriteLine($"DNS via Proxy: {(dnsViaProxy ? "Enabled" : "Disabled")}");

            if (!ProxyBridgeNative.ProxyBridge_SetProxyConfig(
                proxyInfo.Type,
                proxyInfo.Host,
                proxyInfo.Port,
                proxyInfo.Username ?? "",
                proxyInfo.Password ?? ""))
            {
                Console.WriteLine("ERROR: Failed to set proxy configuration");
                return 1;
            }

            ProxyBridgeNative.ProxyBridge_SetDnsViaProxy(dnsViaProxy);

            if (parsedRules.Count > 0)
            {
                Console.WriteLine($"Rules: {parsedRules.Count}");
                foreach (var rule in parsedRules)
                {
                    var ruleId = ProxyBridgeNative.ProxyBridge_AddRule(
                        rule.ProcessName,
                        rule.TargetHosts,
                        rule.TargetPorts,
                        rule.Protocol,
                        rule.Action);

                    if (ruleId > 0)
                    {
                        Console.WriteLine($"  [{ruleId}] {rule.ProcessName}:{rule.TargetHosts}:{rule.TargetPorts}:{rule.Protocol} -> {rule.Action}");
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
                await Task.Delay(100);
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
        // Verbose 1 = logs only, Verbose 3 = both
        if (_verboseLevel == 1 || _verboseLevel == 3)
        {
            Console.WriteLine($"[LOG] {message}");
        }
    }

    private static void OnConnection(string processName, uint pid, string destIp, ushort destPort, string proxyInfo)
    {
        // Verbose 2 = connections only, Verbose 3 = both
        if (_verboseLevel == 2 || _verboseLevel == 3)
        {
            Console.WriteLine($"[CONN] {processName} (PID:{pid}) -> {destIp}:{destPort} via {proxyInfo}");
        }
    }

    private static async Task<List<(string ProcessName, string TargetHosts, string TargetPorts, ProxyBridgeNative.RuleProtocol Protocol, ProxyBridgeNative.RuleAction Action)>> LoadRulesFromFile(string filePath)
    {
        var rules = new List<(string, string, string, ProxyBridgeNative.RuleProtocol, ProxyBridgeNative.RuleAction)>();

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Rule file not found: {filePath}");
        }

        try
        {
            var json = await File.ReadAllTextAsync(filePath);
            var importedRules = System.Text.Json.JsonSerializer.Deserialize(json, ProxyRuleJsonContext.Default.ListProxyRuleImport);

            if (importedRules == null || importedRules.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"WARNING: No rules found in file: {filePath}");
                Console.ResetColor();
                return rules;
            }

            Console.WriteLine($"Loaded {importedRules.Count} rule(s) from: {filePath}");

            foreach (var rule in importedRules)
            {
                if (!rule.Enabled)
                {
                    Console.WriteLine($"  Skipping disabled rule: {rule.ProcessNames}");
                    continue;
                }

                var protocol = rule.Protocol.ToUpper() switch
                {
                    "TCP" => ProxyBridgeNative.RuleProtocol.TCP,
                    "UDP" => ProxyBridgeNative.RuleProtocol.UDP,
                    "BOTH" => ProxyBridgeNative.RuleProtocol.BOTH,
                    _ => throw new ArgumentException($"Invalid protocol in rule file: {rule.Protocol}")
                };

                var action = rule.Action.ToUpper() switch
                {
                    "PROXY" => ProxyBridgeNative.RuleAction.PROXY,
                    "DIRECT" => ProxyBridgeNative.RuleAction.DIRECT,
                    "BLOCK" => ProxyBridgeNative.RuleAction.BLOCK,
                    _ => throw new ArgumentException($"Invalid action in rule file: {rule.Action}")
                };

                rules.Add((rule.ProcessNames, rule.TargetHosts, rule.TargetPorts, protocol, action));
            }

            return rules;
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new ArgumentException($"Invalid JSON format in rule file: {ex.Message}");
        }
    }

    private static (ProxyBridgeNative.ProxyType Type, string Host, ushort Port, string? Username, string? Password) ParseProxyConfig(string proxyUrl)
    {
        string? username = null;
        string? password = null;

        if (proxyUrl.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase))
        {
            var parts = proxyUrl.Substring(9).Split(':');
            if (parts.Length >= 2 && ushort.TryParse(parts[1], out ushort port))
            {
                if (parts.Length >= 4)
                {
                    username = parts[2];
                    password = parts[3];
                }
                return (ProxyBridgeNative.ProxyType.SOCKS5, parts[0], port, username, password);
            }
        }
        else if (proxyUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            var parts = proxyUrl.Substring(7).Split(':');
            if (parts.Length >= 2 && ushort.TryParse(parts[1], out ushort port))
            {
                if (parts.Length >= 4)
                {
                    username = parts[2];
                    password = parts[3];
                }
                return (ProxyBridgeNative.ProxyType.HTTP, parts[0], port, username, password);
            }
        }

        throw new ArgumentException($"Invalid proxy format: {proxyUrl}\nUse type://host:port or type://host:port:username:password");
    }

    private static List<(string ProcessName, string TargetHosts, string TargetPorts, ProxyBridgeNative.RuleProtocol Protocol, ProxyBridgeNative.RuleAction Action)> ParseRules(string[] rules)
    {
        var parsedRules = new List<(string, string, string, ProxyBridgeNative.RuleProtocol, ProxyBridgeNative.RuleAction)>();

        foreach (var rule in rules)
        {
            // Split by colon, but limit to 5 parts to allow colons in other fields if needed
            var parts = rule.Split(':', 5);
            if (parts.Length != 5)
            {
                throw new ArgumentException($"Invalid rule format: {rule}\nExpected format: process:hosts:ports:protocol:action");
            }

            // Don't trim semicolons - they are valid separators for multiple values
            var processName = parts[0].Trim();
            var targetHosts = parts[1].Trim();
            var targetPorts = parts[2].Trim();
            var protocolStr = parts[3].Trim().ToUpper();
            var actionStr = parts[4].Trim().ToUpper();

            // Handle empty fields - use "*" as default
            if (string.IsNullOrWhiteSpace(processName)) processName = "*";
            if (string.IsNullOrWhiteSpace(targetHosts)) targetHosts = "*";
            if (string.IsNullOrWhiteSpace(targetPorts)) targetPorts = "*";

            var protocol = protocolStr switch
            {
                "TCP" => ProxyBridgeNative.RuleProtocol.TCP,
                "UDP" => ProxyBridgeNative.RuleProtocol.UDP,
                "BOTH" => ProxyBridgeNative.RuleProtocol.BOTH,
                _ => throw new ArgumentException($"Invalid protocol: {protocolStr}. Use TCP, UDP, or BOTH")
            };

            var action = actionStr switch
            {
                "PROXY" => ProxyBridgeNative.RuleAction.PROXY,
                "DIRECT" => ProxyBridgeNative.RuleAction.DIRECT,
                "BLOCK" => ProxyBridgeNative.RuleAction.BLOCK,
                _ => throw new ArgumentException($"Invalid action: {actionStr}. Use PROXY, DIRECT, or BLOCK")
            };

            parsedRules.Add((processName, targetHosts, targetPorts, protocol, action));
        }

        return parsedRules;
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
        Console.WriteLine("                      |___/                      |___/  V3.0.0");
        Console.WriteLine();
        Console.WriteLine("  Universal proxy client for Windows applications");
        Console.WriteLine();
        Console.WriteLine("\tAuthor: Sourav Kalal/InterceptSuite");
        Console.WriteLine("\tGitHub: https://github.com/InterceptSuite/ProxyBridge");
        Console.WriteLine();
    }

    private static async Task CheckAndUpdate()
    {
        ShowBanner();
        Console.WriteLine("Checking for updates...\n");

        // Get version from assembly
        var currentVersion = System.Reflection.Assembly.GetExecutingAssembly()
            .GetName().Version?.ToString(3) ?? "0.0.0";

        const string repoOwner = "InterceptSuite";
        const string repoName = "ProxyBridge";

        try
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "ProxyBridge-CLI");

            var apiUrl = $"https://api.github.com/repos/{repoOwner}/{repoName}/releases/latest";
            var response = await httpClient.GetStringAsync(apiUrl);

            using var jsonDoc = System.Text.Json.JsonDocument.Parse(response);
            var root = jsonDoc.RootElement;

            var latestVersionStr = root.GetProperty("tag_name").GetString()?.TrimStart('v') ?? "";
            var releaseName = root.GetProperty("name").GetString() ?? "Unknown";

            Console.WriteLine($"Current version: {currentVersion}");
            Console.WriteLine($"Latest version:  {latestVersionStr}");
            Console.WriteLine();


            if (!Version.TryParse(currentVersion, out var currentVer))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: Invalid current version format.");
                Console.ResetColor();
                return;
            }

            if (!Version.TryParse(latestVersionStr, out var latestVer))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: Invalid latest version format from GitHub.");
                Console.ResetColor();
                return;
            }

            if (latestVer <= currentVer)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✓ You are using the latest version!");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"⚠ New version available: {releaseName}");
            Console.ResetColor();
            Console.WriteLine();


            var assets = root.GetProperty("assets").EnumerateArray();
            string? setupUrl = null;
            string? setupName = null;

            foreach (var asset in assets)
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    (name.Contains("setup", StringComparison.OrdinalIgnoreCase) ||
                     name.Contains("installer", StringComparison.OrdinalIgnoreCase)))
                {
                    setupUrl = asset.GetProperty("browser_download_url").GetString();
                    setupName = name;
                    break;
                }
            }

            if (string.IsNullOrEmpty(setupUrl))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: Setup installer not found in latest release.");
                Console.ResetColor();
                Console.WriteLine($"Visit: https://github.com/{repoOwner}/{repoName}/releases/latest");
                return;
            }

            Console.WriteLine($"Downloading: {setupName}");
            Console.WriteLine($"From: {setupUrl}");
            Console.WriteLine();

            var tempPath = Path.Combine(Path.GetTempPath(), setupName!);
            var setupBytes = await httpClient.GetByteArrayAsync(setupUrl);
            await File.WriteAllBytesAsync(tempPath, setupBytes);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✓ Downloaded to: {tempPath}");
            Console.ResetColor();
            Console.WriteLine();


            Console.WriteLine("Launching installer...");
            var processInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = tempPath,
                UseShellExecute = true,
                Verb = "runas"
            };

            System.Diagnostics.Process.Start(processInfo);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✓ Installer launched successfully!");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ERROR: {ex.Message}");
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine($"Visit: https://github.com/{repoOwner}/{repoName}/releases/latest");
        }
    }
}

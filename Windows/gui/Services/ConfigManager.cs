using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyBridge.GUI.ViewModels;

namespace ProxyBridge.GUI.Services;

public class AppConfig
{
    public string ProxyType { get; set; } = "SOCKS5";
    public string ProxyIp { get; set; } = "";
    public string ProxyPort { get; set; } = "";
    public string ProxyUsername { get; set; } = "";
    public string ProxyPassword { get; set; } = "";
    public bool DnsViaProxy { get; set; } = true;
    public string Language { get; set; } = "en";
    public bool CloseToTray { get; set; } = true;
    public List<ProxyRuleConfig> ProxyRules { get; set; } = new();
}

public class ProxyRuleConfig
{
    public string ProcessName { get; set; } = "";
    public string TargetHosts { get; set; } = "*";
    public string TargetPorts { get; set; } = "*";
    public string Protocol { get; set; } = "TCP";
    public string Action { get; set; } = "PROXY";
    public bool IsEnabled { get; set; } = true;
}

[JsonSerializable(typeof(AppConfig))]
[JsonSerializable(typeof(ProxyRuleConfig))]
[JsonSerializable(typeof(List<ProxyRuleConfig>))]
internal partial class AppConfigJsonContext : JsonSerializerContext
{
}

public static class ConfigManager
{
    private static readonly string ConfigDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "ProxyBridge"
    );
    // C:\Users\<username>\AppData\Roaming\ProxyBridge\config.json

    private static readonly string ConfigFilePath = Path.Combine(ConfigDirectory, "config.json");

    public static bool SaveConfig(AppConfig config)
    {
        try
        {
            if (!Directory.Exists(ConfigDirectory))
            {
                Directory.CreateDirectory(ConfigDirectory);
            }

            var json = JsonSerializer.Serialize(config, AppConfigJsonContext.Default.AppConfig);
            File.WriteAllText(ConfigFilePath, json);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static AppConfig LoadConfig()
    {
        try
        {
            if (!File.Exists(ConfigFilePath))
            {
                return new AppConfig();
            }

            var json = File.ReadAllText(ConfigFilePath);
            var config = JsonSerializer.Deserialize(json, AppConfigJsonContext.Default.AppConfig);
            return config ?? new AppConfig();
        }
        catch
        {
            return new AppConfig();
        }
    }

    public static bool ConfigExists()
    {
        return File.Exists(ConfigFilePath);
    }
}

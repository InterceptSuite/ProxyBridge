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
    public bool IsTrafficLoggingEnabled { get; set; } = true;
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

internal static class AtomicFileHelper
{
    public static bool AtomicWrite(string filePath, string content)
    {
        var tempPath = filePath + ".tmp";
        try
        {
            var directory = Path.GetDirectoryName(filePath);
            if (directory != null && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(tempPath, content);
            File.Move(tempPath, filePath, overwrite: true);
            return true;
        }
        catch
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch { }
            return false;
        }
    }

    public static string? SafeReadFile(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                return null;
            }

            var content = File.ReadAllText(filePath);
            return string.IsNullOrWhiteSpace(content) ? null : content;
        }
        catch
        {
            return null;
        }
    }
}

public static class ConfigManager
{
    private static readonly string ConfigDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "ProxyBridge"
    );

    private static readonly string ConfigFilePath = Path.Combine(ConfigDirectory, "config.json");

    public static bool SaveConfig(AppConfig config)
    {
        var json = JsonSerializer.Serialize(config, AppConfigJsonContext.Default.AppConfig);
        return AtomicFileHelper.AtomicWrite(ConfigFilePath, json);
    }

    public static AppConfig LoadConfig()
    {
        var json = AtomicFileHelper.SafeReadFile(ConfigFilePath);
        if (json == null)
        {
            return new AppConfig();
        }

        try
        {
            var config = JsonSerializer.Deserialize(json, AppConfigJsonContext.Default.AppConfig);
            if (config != null)
            {
                config.ProxyRules ??= new List<ProxyRuleConfig>();
                return config;
            }
        }
        catch { }

        return new AppConfig();
    }

    public static bool ConfigExists()
    {
        return File.Exists(ConfigFilePath);
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProxyBridge.GUI.Services;

public class ProxyConfigEntry
{
    public uint Id { get; set; }
    public string Type { get; set; } = "SOCKS5";
    public string Host { get; set; } = "";
    public string Port { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class ProxyRuleConfig
{
    public string ProcessName { get; set; } = "";
    public string TargetHosts { get; set; } = "*";
    public string TargetPorts { get; set; } = "*";
    public string Protocol { get; set; } = "TCP";
    public string Action { get; set; } = "PROXY";
    public bool IsEnabled { get; set; } = true;
    public uint ProxyConfigId { get; set; } = 0;
}

public class ProxyProfile
{
    public string Version { get; set; } = "1.0";
    public string Name { get; set; } = "Default";
    public bool DnsViaProxy { get; set; } = true;
    public bool LocalhostViaProxy { get; set; } = false;
    public bool IsTrafficLoggingEnabled { get; set; } = true;
    public string Language { get; set; } = "en";
    public bool CloseToTray { get; set; } = true;
    public List<ProxyConfigEntry> ProxyConfigs { get; set; } = new();
    public List<ProxyRuleConfig> ProxyRules { get; set; } = new();
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(ProxyProfile))]
[JsonSerializable(typeof(ProxyConfigEntry))]
[JsonSerializable(typeof(List<ProxyConfigEntry>))]
[JsonSerializable(typeof(ProxyRuleConfig))]
[JsonSerializable(typeof(List<ProxyRuleConfig>))]
internal partial class ProxyProfileJsonContext : JsonSerializerContext { }

internal static class AtomicFileHelper
{
    public static bool AtomicWrite(string filePath, string content)
    {
        var tempPath = filePath + ".tmp";
        try
        {
            var directory = Path.GetDirectoryName(filePath);
            if (directory != null && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            File.WriteAllText(tempPath, content);
            File.Move(tempPath, filePath, overwrite: true);
            return true;
        }
        catch
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            return false;
        }
    }

    public static string? SafeReadFile(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return null;
            var content = File.ReadAllText(filePath);
            return string.IsNullOrWhiteSpace(content) ? null : content;
        }
        catch { return null; }
    }
}

public static class ProfileManager
{
    private const string ProfileVersion = "1.0";
    public const string ProfileExtension = ".pbprofile";
    public const string DefaultProfileName = "Default";

    private static readonly string ProfilesDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "ProxyBridge",
        "profiles"
    );

    public static string[] GetProfileNames()
    {
        EnsureDirectory();
        return Directory.GetFiles(ProfilesDirectory, $"*{ProfileExtension}")
            .Select(f => Path.GetFileNameWithoutExtension(f))
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static bool ProfileExists(string name)
        => File.Exists(GetProfilePath(name));

    public static ProxyProfile LoadProfile(string name)
    {
        var json = AtomicFileHelper.SafeReadFile(GetProfilePath(name));
        if (json == null) return CreateDefault(name);

        try
        {
            var profile = JsonSerializer.Deserialize(json, ProxyProfileJsonContext.Default.ProxyProfile);
            if (profile == null || profile.Version != ProfileVersion) return CreateDefault(name);

            profile.ProxyRules ??= new List<ProxyRuleConfig>();
            profile.ProxyConfigs ??= new List<ProxyConfigEntry>();
            profile.Name = name;
            return profile;
        }
        catch
        {
            return CreateDefault(name);
        }
    }

    public static bool SaveProfile(string name, ProxyProfile profile)
    {
        EnsureDirectory();
        profile.Name = name;
        profile.Version = ProfileVersion;
        var json = JsonSerializer.Serialize(profile, ProxyProfileJsonContext.Default.ProxyProfile);
        return AtomicFileHelper.AtomicWrite(GetProfilePath(name), json);
    }

    public static bool DeleteProfile(string name)
    {
        try
        {
            var path = GetProfilePath(name);
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
        catch { return false; }
    }

    public static bool RenameProfile(string oldName, string newName)
    {
        try
        {
            var oldPath = GetProfilePath(oldName);
            var newPath = GetProfilePath(newName);
            if (!File.Exists(oldPath) || File.Exists(newPath)) return false;
            File.Move(oldPath, newPath);
            return true;
        }
        catch { return false; }
    }

    // Returns the name assigned to the imported profile, or null on failure.
    public static string? ImportProfile(string sourcePath)
    {
        try
        {
            sourcePath = Path.GetFullPath(sourcePath);
            var json = File.ReadAllText(sourcePath);
            var profile = JsonSerializer.Deserialize(json, ProxyProfileJsonContext.Default.ProxyProfile);
            if (profile == null) return null;

            profile.Version = ProfileVersion;
            profile.ProxyRules ??= new List<ProxyRuleConfig>();
            profile.ProxyConfigs ??= new List<ProxyConfigEntry>();

            var baseName = SanitizeProfileName(Path.GetFileNameWithoutExtension(sourcePath));
            var name = GetUniqueName(baseName);
            SaveProfile(name, profile);
            return name;
        }
        catch { return null; }
    }

    public static bool ExportProfile(string name, string destinationPath)
    {
        try
        {
            var sourcePath = GetProfilePath(name);
            if (!File.Exists(sourcePath)) return false;
            destinationPath = Path.GetFullPath(destinationPath);
            File.Copy(sourcePath, destinationPath, overwrite: true);
            return true;
        }
        catch { return false; }
    }

    public static bool IsValidProfileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 64) return false;
        var invalid = Path.GetInvalidFileNameChars();
        return !name.Any(c => invalid.Contains(c));
    }

    private static string GetProfilePath(string name)
        => Path.Combine(ProfilesDirectory, name + ProfileExtension);

    private static void EnsureDirectory()
    {
        if (!Directory.Exists(ProfilesDirectory))
            Directory.CreateDirectory(ProfilesDirectory);
    }

    private static ProxyProfile CreateDefault(string name) => new() { Name = name };

    private static string SanitizeProfileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sanitized = new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray()).Trim();
        if (string.IsNullOrWhiteSpace(sanitized)) return "Imported";
        return sanitized.Length <= 64 ? sanitized : sanitized[..64];
    }

    private static string GetUniqueName(string baseName)
    {
        if (!ProfileExists(baseName)) return baseName;
        for (int i = 2; i <= 99; i++)
        {
            var candidate = $"{baseName} ({i})";
            if (!ProfileExists(candidate)) return candidate;
        }
        return baseName + "_" + Guid.NewGuid().ToString("N")[..8];
    }
}

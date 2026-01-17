using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace ProxyBridge.GUI.Services;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AppSettings))]
internal partial class AppSettingsContext : JsonSerializerContext
{
}

public class SettingsService
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "ProxyBridge",
        "settings.json");

    public AppSettings LoadSettings()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var settings = JsonSerializer.Deserialize(json, AppSettingsContext.Default.AppSettings);
                return settings ?? new AppSettings();
            }
        }
        catch
        {
            // If there's any error loading settings, return defaults
        }

        return new AppSettings();
    }

    public void SaveSettings(AppSettings settings)
    {
        try
        {
            var directory = Path.GetDirectoryName(SettingsPath);
            if (directory != null && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(settings, AppSettingsContext.Default.AppSettings);
            File.WriteAllText(SettingsPath, json);
        }
        catch
        {
        }
    }

    public void SetStartupWithWindows(bool enable)
    {
        const string keyName = "ProxyBridge";
        const string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string approvedKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(runKey, true);
            if (key == null) return;

            if (enable)
            {
                var exePath = Environment.ProcessPath;
                if (exePath != null)
                {
                    key.SetValue(keyName, $"\"{exePath}\" --minimized");

                    using var approvedKeyHandle = Registry.CurrentUser.CreateSubKey(approvedKey, true);
                    if (approvedKeyHandle != null)
                    {
                        byte[] enabledData = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                        approvedKeyHandle.SetValue(keyName, enabledData, RegistryValueKind.Binary);
                    }
                }
            }
            else
            {
                key.DeleteValue(keyName, false);

                using var approvedKeyHandle = Registry.CurrentUser.OpenSubKey(approvedKey, true);
                approvedKeyHandle?.DeleteValue(keyName, false);
            }
        }
        catch
        {
        }
    }

    public bool IsStartupEnabled()
    {
        const string keyName = "ProxyBridge";
        const string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(runKey, false);
            return key?.GetValue(keyName) != null;
        }
        catch
        {
            return false;
        }
    }
}

public class AppSettings
{
    public bool CheckForUpdatesOnStartup { get; set; } = true;
    public DateTime LastUpdateCheck { get; set; } = DateTime.MinValue;
    public bool StartWithWindows { get; set; } = false;
}
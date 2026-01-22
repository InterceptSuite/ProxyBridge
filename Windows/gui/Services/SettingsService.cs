using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

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
        const string taskName = "ProxyBridge";

        try
        {
            var exePath = Environment.ProcessPath;
            if (exePath == null) return;

            if (enable)
            {
                // Adding in registy in  Software\Microsoft\Windows\CurrentVersion\Run is not possible or bad idea
                // app need admin permisison to run with registy not posible or uac at startup whicih is bad idea
                // Possible solution - Windows Service - Have no experience developing serice and its too much work for simple startup load
                // Solution 2 - Task schedule - implemented
                var arguments = $"/Create /F /TN \"{taskName}\" /TR \"\\\"{exePath}\\\" --minimized\" /SC ONLOGON /RL HIGHEST";

                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = System.Diagnostics.Process.Start(startInfo);
                process?.WaitForExit();
            }
            else
            {
                var arguments = $"/Delete /F /TN \"{taskName}\"";

                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = System.Diagnostics.Process.Start(startInfo);
                process?.WaitForExit();
            }
        }
        catch
        {
        }
    }

    public bool IsStartupEnabled()
    {
        const string taskName = "ProxyBridge";

        try
        {
            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Query /TN \"{taskName}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = System.Diagnostics.Process.Start(startInfo);
            if (process == null) return false;

            process.WaitForExit();
            return process.ExitCode == 0;
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
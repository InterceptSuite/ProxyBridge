using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Reflection;
using System.Diagnostics;
using System.Linq;

namespace ProxyBridge.GUI.Services;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(GitHubRelease))]
[JsonSerializable(typeof(GitHubAsset))]
internal partial class SourceGenerationContext : JsonSerializerContext
{
}

public class UpdateService
{
    private readonly HttpClient _httpClient;
    private const string GitHubApiUrl = "https://api.github.com/repos/InterceptSuite/ProxyBridge/releases/latest";

    public UpdateService()
    {
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "ProxyBridge-UpdateChecker");
    }

    public async Task<VersionInfo> CheckForUpdatesAsync()
    {
        try
        {
            var response = await _httpClient.GetStringAsync(GitHubApiUrl);
            var release = JsonSerializer.Deserialize(response, SourceGenerationContext.Default.GitHubRelease);

            var currentVersion = GetCurrentVersion();
            var latestVersion = ParseVersion(release?.TagName);

            // Find the setup executable in assets
            var setupAsset = release?.Assets?.FirstOrDefault(a =>
                a.Name?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true &&
                (a.Name.Contains("setup", StringComparison.OrdinalIgnoreCase) ||
                 a.Name.Contains("installer", StringComparison.OrdinalIgnoreCase) ||
                 a.Name.Contains("ProxyBridge", StringComparison.OrdinalIgnoreCase)));

            return new VersionInfo
            {
                CurrentVersion = currentVersion,
                LatestVersion = latestVersion,
                IsUpdateAvailable = IsNewerVersion(latestVersion, currentVersion),
                LatestVersionString = release?.TagName ?? "Unknown",
                CurrentVersionString = FormatVersion(currentVersion),
                DownloadUrl = setupAsset?.BrowserDownloadUrl,
                SetupFileName = setupAsset?.Name
            };
        }
        catch (Exception ex)
        {
            return new VersionInfo
            {
                CurrentVersion = GetCurrentVersion(),
                LatestVersion = GetCurrentVersion(),
                IsUpdateAvailable = false,
                Error = ex.Message,
                LatestVersionString = "Error",
                CurrentVersionString = FormatVersion(GetCurrentVersion())
            };
        }
    }

    private Version GetCurrentVersion()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        return version ?? new Version(1, 0, 0);
    }

    private Version ParseVersion(string? tagName)
    {
        if (string.IsNullOrEmpty(tagName))
            return new Version(0, 0, 0);

        // Remove 'v' prefix if present
        var versionString = tagName.StartsWith("v") ? tagName.Substring(1) : tagName;

        if (Version.TryParse(versionString, out var version))
            return version;

        return new Version(0, 0, 0);
    }

    private bool IsNewerVersion(Version latest, Version current)
    {
        return latest.CompareTo(current) > 0;
    }

    private string FormatVersion(Version version)
    {
        return $"v{version.Major}.{version.Minor}.{version.Build}";
    }

    public async Task<string?> DownloadUpdateAsync(string downloadUrl, string fileName, IProgress<int>? progress = null)
    {
        try
        {
            var tempPath = Path.Combine(Path.GetTempPath(), fileName);

            using var response = await _httpClient.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? 0;
            var downloadedBytes = 0L;

            using var contentStream = await response.Content.ReadAsStreamAsync();
            using var fileStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None);

            var buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                await fileStream.WriteAsync(buffer, 0, bytesRead);
                downloadedBytes += bytesRead;

                if (totalBytes > 0)
                {
                    var progressPercentage = (int)((downloadedBytes * 100) / totalBytes);
                    progress?.Report(progressPercentage);
                }
            }

            return tempPath;
        }
        catch
        {
            return null;
        }
    }

    public void InstallUpdateAndExit(string installerPath)
    {
        try
        {
            // Start the installer
            var startInfo = new ProcessStartInfo
            {
                FileName = installerPath,
                UseShellExecute = true,
                Verb = "runas" // Run as administrator
            };

            Process.Start(startInfo);

            // Exit the current application
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to start installer: {ex.Message}", ex);
        }
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}

public class VersionInfo
{
    public Version CurrentVersion { get; set; } = new(1, 0, 0);
    public Version LatestVersion { get; set; } = new(1, 0, 0);
    public bool IsUpdateAvailable { get; set; }
    public string? Error { get; set; }
    public string LatestVersionString { get; set; } = "";
    public string CurrentVersionString { get; set; } = "";
    public string? DownloadUrl { get; set; }
    public string? SetupFileName { get; set; }
}

public class GitHubRelease
{
    [JsonPropertyName("tag_name")]
    public string? TagName { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("prerelease")]
    public bool Prerelease { get; set; }

    [JsonPropertyName("published_at")]
    public DateTime PublishedAt { get; set; }

    [JsonPropertyName("assets")]
    public GitHubAsset[]? Assets { get; set; }
}

public class GitHubAsset
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("browser_download_url")]
    public string? BrowserDownloadUrl { get; set; }

    [JsonPropertyName("size")]
    public long Size { get; set; }
}
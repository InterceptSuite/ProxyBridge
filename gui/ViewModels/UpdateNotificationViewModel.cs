using System;
using System.Windows.Input;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using ProxyBridge.GUI.Services;

namespace ProxyBridge.GUI.ViewModels;

public class UpdateNotificationViewModel : ViewModelBase
{
    private readonly UpdateService _updateService;
    private readonly SettingsService _settingsService;
    private readonly Action _onClose;
    private readonly VersionInfo _versionInfo;

    private string _currentVersion = "";
    private string _latestVersion = "";
    private string _downloadStatus = "";
    private string _errorMessage = "";
    private double _downloadProgress = 0;
    private bool _isDownloading = false;
    private bool _hasError = false;

    public UpdateNotificationViewModel() : this(() => { }, new VersionInfo())
    {
    }

    public UpdateNotificationViewModel(Action onClose, VersionInfo versionInfo)
    {
        _updateService = new UpdateService();
        _settingsService = new SettingsService();
        _onClose = onClose;
        _versionInfo = versionInfo;

        CurrentVersion = versionInfo.CurrentVersionString;
        LatestVersion = versionInfo.LatestVersionString;

        UpdateNowCommand = new RelayCommand(async () => await DownloadAndInstallAsync());
        DontAskAgainCommand = new RelayCommand(DontAskAgain);
        LaterCommand = new RelayCommand(_onClose);
    }

    public string CurrentVersion
    {
        get => _currentVersion;
        set => SetProperty(ref _currentVersion, value);
    }

    public string LatestVersion
    {
        get => _latestVersion;
        set => SetProperty(ref _latestVersion, value);
    }

    public string DownloadStatus
    {
        get => _downloadStatus;
        set => SetProperty(ref _downloadStatus, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        set => SetProperty(ref _errorMessage, value);
    }

    public double DownloadProgress
    {
        get => _downloadProgress;
        set => SetProperty(ref _downloadProgress, value);
    }

    public bool IsDownloading
    {
        get => _isDownloading;
        set => SetProperty(ref _isDownloading, value);
    }

    public bool HasError
    {
        get => _hasError;
        set => SetProperty(ref _hasError, value);
    }

    public ICommand UpdateNowCommand { get; }
    public ICommand DontAskAgainCommand { get; }
    public ICommand LaterCommand { get; }

    private async Task DownloadAndInstallAsync()
    {
        IsDownloading = true;
        HasError = false;
        ErrorMessage = "";
        DownloadProgress = 0;
        DownloadStatus = "Starting download...";

        try
        {
            if (string.IsNullOrEmpty(_versionInfo.DownloadUrl))
            {
                throw new Exception("Could not find download URL for the latest version");
            }

            var tempPath = Path.GetTempPath();
            var fileName = _versionInfo.SetupFileName ?? "ProxyBridge-Setup.exe";
            var filePath = Path.Combine(tempPath, fileName);

            DownloadStatus = "Downloading update...";

            using var httpClient = new HttpClient();
            using var response = await httpClient.GetAsync(_versionInfo.DownloadUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? -1L;
            using var contentStream = await response.Content.ReadAsStreamAsync();
            using var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true);

            var buffer = new byte[8192];
            long totalBytesRead = 0;
            int bytesRead;

            while ((bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                await fileStream.WriteAsync(buffer, 0, bytesRead);
                totalBytesRead += bytesRead;

                if (totalBytes > 0)
                {
                    DownloadProgress = (double)totalBytesRead / totalBytes * 100;
                    DownloadStatus = $"Downloaded {totalBytesRead / 1024 / 1024:F1} MB of {totalBytes / 1024 / 1024:F1} MB";
                }
                else
                {
                    DownloadStatus = $"Downloaded {totalBytesRead / 1024 / 1024:F1} MB";
                }
            }

            DownloadStatus = "Download complete. Starting installation...";
            DownloadProgress = 100;

            // Start the installer and exit the current application
            Process.Start(new ProcessStartInfo
            {
                FileName = filePath,
                UseShellExecute = true
            });

            // Close the current application
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            HasError = true;
            ErrorMessage = $"Error downloading update: {ex.Message}";
            DownloadStatus = "Download failed";
        }
        finally
        {
            IsDownloading = false;
        }
    }

    private void DontAskAgain()
    {
        var settings = _settingsService.LoadSettings();
        settings.CheckForUpdatesOnStartup = false;
        _settingsService.SaveSettings(settings);
        _onClose();
    }
}
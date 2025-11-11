using System;
using System.Windows.Input;
using System.Threading.Tasks;
using ProxyBridge.GUI.Services;

namespace ProxyBridge.GUI.ViewModels;

public class UpdateCheckViewModel : ViewModelBase
{
    private readonly UpdateService _updateService;
    private readonly Action _onClose;
    private string _currentVersion = "";
    private string _latestVersion = "";
    private string _statusMessage = "";
    private string _statusColor = "#FFB0B0B0";
    private string _latestVersionColor = "#FFB0B0B0";
    private string _errorMessage = "";
    private bool _isChecking = false;
    private bool _hasError = false;
    private bool _isUpdateAvailable = false;
    private bool _isDownloading = false;
    private int _downloadProgress = 0;
    private string _downloadStatus = "";
    private VersionInfo? _currentVersionInfo;

    public UpdateCheckViewModel() : this(() => { })
    {
    }

    public UpdateCheckViewModel(Action onClose)
    {
        _updateService = new UpdateService();
        _onClose = onClose;

        CheckUpdatesCommand = new RelayCommand(async () => await CheckForUpdatesAsync());
        DownloadNowCommand = new RelayCommand(async () => await DownloadAndInstallAsync(), () => IsUpdateAvailable && !IsDownloading);
        CloseCommand = new RelayCommand(onClose);

        // Start checking immediately
        _ = CheckForUpdatesAsync();
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

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string StatusColor
    {
        get => _statusColor;
        set => SetProperty(ref _statusColor, value);
    }

    public string LatestVersionColor
    {
        get => _latestVersionColor;
        set => SetProperty(ref _latestVersionColor, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        set => SetProperty(ref _errorMessage, value);
    }

    public bool IsChecking
    {
        get => _isChecking;
        set => SetProperty(ref _isChecking, value);
    }

    public bool HasError
    {
        get => _hasError;
        set => SetProperty(ref _hasError, value);
    }

    public bool IsUpdateAvailable
    {
        get => _isUpdateAvailable;
        set => SetProperty(ref _isUpdateAvailable, value);
    }

    public bool IsDownloading
    {
        get => _isDownloading;
        set => SetProperty(ref _isDownloading, value);
    }

    public int DownloadProgress
    {
        get => _downloadProgress;
        set => SetProperty(ref _downloadProgress, value);
    }

    public string DownloadStatus
    {
        get => _downloadStatus;
        set => SetProperty(ref _downloadStatus, value);
    }

    public ICommand CheckUpdatesCommand { get; }
    public ICommand DownloadNowCommand { get; }
    public ICommand CloseCommand { get; }

    private async Task CheckForUpdatesAsync()
    {
        IsChecking = true;
        HasError = false;
        StatusMessage = "";
        ErrorMessage = "";

        try
        {
            var versionInfo = await _updateService.CheckForUpdatesAsync();
            _currentVersionInfo = versionInfo;

            CurrentVersion = versionInfo.CurrentVersionString;
            LatestVersion = versionInfo.LatestVersionString;
            IsUpdateAvailable = versionInfo.IsUpdateAvailable;

            if (!string.IsNullOrEmpty(versionInfo.Error))
            {
                HasError = true;
                ErrorMessage = $"Error checking for updates: {versionInfo.Error}";
                StatusMessage = "Unable to check for updates";
                StatusColor = "#FFFF6B6B";
                LatestVersionColor = "#FFFF6B6B";
            }
            else if (versionInfo.IsUpdateAvailable)
            {
                StatusMessage = "New version available!";
                StatusColor = "#FF4CAF50";
                LatestVersionColor = "#FF4CAF50";
            }
            else
            {
                StatusMessage = "You have the latest version";
                StatusColor = "#FF4CAF50";
                LatestVersionColor = "#FF007ACC";
            }

            // Refresh command can execute state
            (DownloadNowCommand as RelayCommand)?.RaiseCanExecuteChanged();
        }
        catch (Exception ex)
        {
            HasError = true;
            ErrorMessage = $"Error checking for updates: {ex.Message}";
            StatusMessage = "Unable to check for updates";
            StatusColor = "#FFFF6B6B";
            LatestVersionColor = "#FFFF6B6B";
        }
        finally
        {
            IsChecking = false;
        }
    }

    private async Task DownloadAndInstallAsync()
    {
        if (_currentVersionInfo?.DownloadUrl == null || _currentVersionInfo?.SetupFileName == null)
        {
            ErrorMessage = "Download URL not available";
            HasError = true;
            return;
        }

        IsDownloading = true;
        DownloadProgress = 0;
        DownloadStatus = "Starting download...";
        HasError = false;
        ErrorMessage = "";

        try
        {
            var progress = new Progress<int>(percent =>
            {
                DownloadProgress = percent;
                DownloadStatus = $"Downloading... {percent}%";
            });

            var installerPath = await _updateService.DownloadUpdateAsync(
                _currentVersionInfo.DownloadUrl,
                _currentVersionInfo.SetupFileName,
                progress);

            if (installerPath != null)
            {
                DownloadStatus = "Download complete. Starting installer...";
                await Task.Delay(1000); // Brief pause to show completion

                // This will close the current app and start the installer
                _updateService.InstallUpdateAndExit(installerPath);
            }
            else
            {
                HasError = true;
                ErrorMessage = "Failed to download the update";
                DownloadStatus = "Download failed";
            }
        }
        catch (Exception ex)
        {
            HasError = true;
            ErrorMessage = $"Download error: {ex.Message}";
            DownloadStatus = "Download failed";
        }
        finally
        {
            IsDownloading = false;
            (DownloadNowCommand as RelayCommand)?.RaiseCanExecuteChanged();
        }
    }
}
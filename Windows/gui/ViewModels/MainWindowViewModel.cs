using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Threading;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using ProxyBridge.GUI.Views;
using ProxyBridge.GUI.Services;
using ProxyBridge.GUI.Common;

namespace ProxyBridge.GUI.ViewModels;

public class MainWindowViewModel : ViewModelBase
{
    private const int MAX_CONNECTION_LOG_LINES = 100;
    private const int MAX_ACTIVITY_LOG_LINES = 100;

    private string _title = "ProxyBridge";
    private int _selectedTabIndex;
    private string _connectionsLog = "";
    private string _activityLog = "";
    private string _connectionsSearchText = "";
    private string _activitySearchText = "";
    private string _filteredConnectionsLog = "";
    private string _filteredActivityLog = "";
    private bool _isProxyRulesDialogOpen;
    private bool _isProxySettingsDialogOpen;
    private bool _isAddRuleViewOpen;
    private string _newProcessName = "";
    private string _newProxyAction = "PROXY";
    private bool _startWithWindows;
    private Window? _mainWindow;
    private ProxyBridgeService? _proxyService;
    private bool _isServiceInitialized = false;
    private readonly SettingsService _settingsService = new();
    private string _activeProfileName = ProfileManager.DefaultProfileName;

    public ObservableCollection<ProxyConfig> ProxyConfigs { get; } = new();
    public ObservableCollection<ProxyRule> ProxyRules { get; } = new();
    public ObservableCollection<string> SwitchProfileItems { get; } = new();

    private readonly List<string> _pendingConnectionLogs = new(128);
    private readonly List<string> _pendingActivityLogs = new(64);
    private readonly object _connectionLogLock = new();
    private readonly object _activityLogLock = new();
    private DispatcherTimer? _connectionLogTimer;
    private DispatcherTimer? _activityLogTimer;

    public void SetMainWindow(Window window)
    {
        _mainWindow = window;

        if (_isServiceInitialized)
            return;

        _isServiceInitialized = true;
        LoadConfiguration();

        try
        {
            _proxyService = new ProxyBridgeService();
            _proxyService.LogReceived += (msg) =>
            {
                lock (_activityLogLock)
                    _pendingActivityLogs.Add($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
            };

            _proxyService.ConnectionReceived += (processName, pid, destIp, destPort, proxyInfo) =>
            {
                if (!_isTrafficLoggingEnabled)
                    return;

                if (_connectionLogTimer?.IsEnabled == false)
                    _connectionLogTimer.Start();

                lock (_connectionLogLock)
                    _pendingConnectionLogs.Add($"[{DateTime.Now:HH:mm:ss}] {processName} (PID:{pid}) -> {destIp}:{destPort} via {proxyInfo}\n");
            };

            _connectionLogTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _connectionLogTimer.Tick += (s, e) =>
            {
                List<string> logsToAdd;
                lock (_connectionLogLock)
                {
                    if (_pendingConnectionLogs.Count == 0) return;
                    logsToAdd = new List<string>(_pendingConnectionLogs);
                    _pendingConnectionLogs.Clear();
                }

                ConnectionsLog += string.Join("", logsToAdd);

                var lines = ConnectionsLog.Split('\n');
                if (lines.Length > MAX_CONNECTION_LOG_LINES)
                    ConnectionsLog = string.Join("\n", lines.Skip(lines.Length - MAX_CONNECTION_LOG_LINES));
            };

            _activityLogTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            _activityLogTimer.Tick += (s, e) =>
            {
                List<string> logsToAdd;
                lock (_activityLogLock)
                {
                    if (_pendingActivityLogs.Count == 0) return;
                    logsToAdd = new List<string>(_pendingActivityLogs);
                    _pendingActivityLogs.Clear();
                }
                ActivityLog += string.Join("", logsToAdd);
            };
            _activityLogTimer.Start();

            _proxyService.SetDnsViaProxy(_dnsViaProxy);
            _proxyService.SetLocalhostViaProxy(_localhostViaProxy);

            // Build stored-ID to native-ID map while registering proxy configs
            var configIdMap = new Dictionary<uint, uint>();
            foreach (var pc in ProxyConfigs)
            {
                if (string.IsNullOrWhiteSpace(pc.Host) || !ushort.TryParse(pc.Port, out ushort port)) continue;
                uint nativeId = _proxyService.AddProxyConfig(pc.Type, pc.Host, port, pc.Username, pc.Password);
                if (nativeId > 0)
                {
                    if (pc.Id > 0) configIdMap[pc.Id] = nativeId;
                    pc.Id = nativeId;
                }
            }

            if (_proxyService.Start())
            {
                foreach (var rule in ProxyRules)
                {
                    uint nativeProxyId = 0;
                    if (rule.ProxyConfigId > 0)
                        configIdMap.TryGetValue(rule.ProxyConfigId, out nativeProxyId);
                    rule.ProxyConfigId = nativeProxyId;

                    uint ruleId = _proxyService.AddRule(
                        rule.ProcessName, rule.TargetHosts, rule.TargetPorts,
                        rule.Protocol, rule.Action, nativeProxyId);

                    if (ruleId > 0)
                    {
                        rule.RuleId = ruleId;
                        rule.Index = ProxyRules.IndexOf(rule) + 1;
                    }
                }

                foreach (var rule in ProxyRules)
                {
                    if (rule.Action == "PROXY" && rule.ProxyConfigId > 0)
                    {
                        var pc = ProxyConfigs.FirstOrDefault(p => p.Id == rule.ProxyConfigId);
                        rule.ProxyConfigDisplay = pc?.DisplayName ?? "";
                    }
                }
            }
            else
            {
                QueueActivityLog("ERROR: Failed to start ProxyBridge service");
            }
        }
        catch (Exception ex)
        {
            QueueActivityLog($"ERROR: {ex.Message}");
        }

        _ = CheckForUpdatesOnStartupAsync();
    }

    public string Title
    {
        get => _title;
        set => SetProperty(ref _title, value);
    }

    public string ActiveProfileName
    {
        get => _activeProfileName;
        private set => SetProperty(ref _activeProfileName, value);
    }

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set => SetProperty(ref _selectedTabIndex, value);
    }

    public string ConnectionsLog
    {
        get => _connectionsLog;
        set
        {
            if (SetProperty(ref _connectionsLog, value))
            {
                if (string.IsNullOrWhiteSpace(_connectionsSearchText))
                    FilteredConnectionsLog = _connectionsLog;
            }
        }
    }

    public string ActivityLog
    {
        get => _activityLog;
        set
        {
            if (SetProperty(ref _activityLog, value))
            {
                if (!string.IsNullOrEmpty(_activityLog))
                {
                    var lines = _activityLog.Split('\n');
                    if (lines.Length > MAX_ACTIVITY_LOG_LINES)
                    {
                        var oldLog = _activityLog;
                        var linesToKeep = lines.Skip(lines.Length - MAX_ACTIVITY_LOG_LINES).ToArray();
                        _activityLog = string.Join("\n", linesToKeep);
                        oldLog = null!;
                    }
                }

                if (string.IsNullOrWhiteSpace(_activitySearchText))
                    FilteredActivityLog = _activityLog;
            }
        }
    }

    public bool IsProxyRulesDialogOpen
    {
        get => _isProxyRulesDialogOpen;
        set => SetProperty(ref _isProxyRulesDialogOpen, value);
    }

    public bool IsProxySettingsDialogOpen
    {
        get => _isProxySettingsDialogOpen;
        set => SetProperty(ref _isProxySettingsDialogOpen, value);
    }

    public bool IsAddRuleViewOpen
    {
        get => _isAddRuleViewOpen;
        set => SetProperty(ref _isAddRuleViewOpen, value);
    }

    public string ConnectionsSearchText
    {
        get => _connectionsSearchText;
        set => SetProperty(ref _connectionsSearchText, value);
    }

    public string ActivitySearchText
    {
        get => _activitySearchText;
        set => SetProperty(ref _activitySearchText, value);
    }

    public string FilteredConnectionsLog
    {
        get => _filteredConnectionsLog;
        set => SetProperty(ref _filteredConnectionsLog, value);
    }

    public string FilteredActivityLog
    {
        get => _filteredActivityLog;
        set => SetProperty(ref _filteredActivityLog, value);
    }

    public string NewProcessName
    {
        get => _newProcessName;
        set => SetProperty(ref _newProcessName, value);
    }

    public string NewProxyAction
    {
        get => _newProxyAction;
        set => SetProperty(ref _newProxyAction, value);
    }

    private bool _dnsViaProxy = true;
    public bool DnsViaProxy
    {
        get => _dnsViaProxy;
        set
        {
            if (SetProperty(ref _dnsViaProxy, value))
            {
                _proxyService?.SetDnsViaProxy(value);
                SaveCurrentProfileAsync();
            }
        }
    }

    private bool _localhostViaProxy = false;
    public bool LocalhostViaProxy
    {
        get => _localhostViaProxy;
        set
        {
            if (SetProperty(ref _localhostViaProxy, value))
            {
                _proxyService?.SetLocalhostViaProxy(value);
                SaveCurrentProfileAsync();
            }
        }
    }

    private bool _isTrafficLoggingEnabled = true;
    public bool IsTrafficLoggingEnabled
    {
        get => _isTrafficLoggingEnabled;
        set
        {
            if (SetProperty(ref _isTrafficLoggingEnabled, value))
            {
                if (value)
                {
                    ProxyBridgeService.SetTrafficLoggingEnabled(true);
                    _connectionLogTimer?.Start();
                }
                else
                {
                    _connectionLogTimer?.Stop();
                    lock (_connectionLogLock)
                    {
                        _pendingConnectionLogs.Clear();
                    }

                    ProxyBridgeService.SetTrafficLoggingEnabled(false);

                    ConnectionsLog = null!;
                    FilteredConnectionsLog = null!;
                    ConnectionsLog = "";
                    FilteredConnectionsLog = "";

                    GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
                    GC.WaitForPendingFinalizers();
                    GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
                }
                SaveCurrentProfileAsync();
            }
        }
    }

    private bool _closeToTray = true;
    public bool CloseToTray
    {
        get => _closeToTray;
        set => SetProperty(ref _closeToTray, value);
    }

    private readonly Loc _loc = Loc.Instance;
    public Loc Loc => _loc;

    private string _currentLanguage = "en";
    private string _englishCheckmark = "✓";
    private string _chineseCheckmark = "";

    public string EnglishCheckmark
    {
        get => _englishCheckmark;
        set => SetProperty(ref _englishCheckmark, value);
    }

    public string ChineseCheckmark
    {
        get => _chineseCheckmark;
        set => SetProperty(ref _chineseCheckmark, value);
    }

    public bool StartWithWindows
    {
        get => _startWithWindows;
        set => SetProperty(ref _startWithWindows, value);
    }

    public ICommand ShowProxySettingsCommand { get; }
    public ICommand ShowProxyRulesCommand { get; }
    public ICommand ShowAboutCommand { get; }
    public ICommand CheckForUpdatesCommand { get; }
    public ICommand ToggleDnsViaProxyCommand { get; }
    public ICommand ToggleLocalhostViaProxyCommand { get; }
    public ICommand ToggleTrafficLoggingCommand { get; }
    public ICommand ToggleCloseToTrayCommand { get; }
    public ICommand ToggleStartWithWindowsCommand { get; }
    public ICommand CloseDialogCommand { get; }
    public ICommand ClearConnectionsLogCommand { get; }
    public ICommand ClearActivityLogCommand { get; }
    public ICommand SearchConnectionsCommand { get; }
    public ICommand SearchActivityCommand { get; }
    public ICommand AddRuleCommand { get; }
    public ICommand SaveNewRuleCommand { get; }
    public ICommand CancelAddRuleCommand { get; }
    public ICommand NewProfileCommand { get; }
    public ICommand RenameProfileCommand { get; }
    public ICommand DeleteProfileCommand { get; }
    public ICommand ImportProfileCommand { get; }
    public ICommand ExportProfileCommand { get; }
    public ICommand SwitchProfileCommand { get; }

    public MainWindowViewModel()
    {
        SwitchProfileCommand = new RelayCommandWithParameter<string>(name =>
        {
            if (string.IsNullOrEmpty(name) || name == _activeProfileName) return;
            SaveCurrentProfile();
            SwitchToProfile(name);
        });

        ShowProxySettingsCommand = new RelayCommand(async () =>
        {
            var window = new ProxySettingsWindow();

            var viewModel = new ProxySettingsViewModel(
                proxyConfigs: ProxyConfigs,
                proxyService: _proxyService,
                onConfigsChanged: SaveCurrentProfileAsync,
                onClose: () => window.Close(),
                countRulesUsingConfig: (id) =>
                    ProxyRules.Count(r => r.Action == "PROXY" && r.ProxyConfigId == id),
                deleteRulesForConfig: (id) =>
                {
                    var toDelete = ProxyRules.Where(r => r.Action == "PROXY" && r.ProxyConfigId == id).ToList();
                    foreach (var rule in toDelete)
                    {
                        _proxyService?.DeleteRule(rule.RuleId);
                        ProxyRules.Remove(rule);
                    }
                    if (toDelete.Count > 0)
                        SaveCurrentProfileAsync();
                }
            );

            window.DataContext = viewModel;
            viewModel.SetWindow(window);

            if (_mainWindow != null)
                await window.ShowDialog(_mainWindow);
        });

        ShowProxyRulesCommand = new RelayCommand(async () =>
        {
            var window = new ProxyRulesWindow();

            var viewModel = new ProxyRulesViewModel(
                proxyRules: ProxyRules,
                availableProxyConfigs: ProxyConfigs,
                onAddRule: (rule) =>
                {
                    if (_proxyService != null)
                    {
                        uint ruleId = _proxyService.AddRule(
                            rule.ProcessName, rule.TargetHosts, rule.TargetPorts,
                            rule.Protocol, rule.Action, rule.ProxyConfigId);
                        if (ruleId > 0)
                        {
                            rule.RuleId = ruleId;
                            rule.Index = ProxyRules.Count + 1;
                            ProxyRules.Add(rule);
                            SaveCurrentProfileAsync();
                        }
                        else
                        {
                            QueueActivityLog("ERROR: Failed to add rule");
                        }
                    }
                },
                onClose: () => window.Close(),
                proxyService: _proxyService,
                onConfigChanged: SaveCurrentProfileAsync
            );

            window.DataContext = viewModel;
            viewModel.SetWindow(window);

            if (_mainWindow != null)
                await window.ShowDialog(_mainWindow);
        });

        ShowAboutCommand = new RelayCommand(async () =>
        {
            var viewModel = new AboutViewModel(() => { });
            var window = new AboutWindow { DataContext = viewModel };
            if (_mainWindow != null)
                await window.ShowDialog(_mainWindow);
        });

        CheckForUpdatesCommand = new RelayCommand(async () =>
        {
            var updateWindow = new UpdateCheckWindow();
            var viewModel = new UpdateCheckViewModel(() => updateWindow.Close());
            updateWindow.DataContext = viewModel;
            if (_mainWindow != null)
                await updateWindow.ShowDialog(_mainWindow);
        });

        ToggleDnsViaProxyCommand = new RelayCommand(() => { DnsViaProxy = !DnsViaProxy; });
        ToggleLocalhostViaProxyCommand = new RelayCommand(() => { LocalhostViaProxy = !LocalhostViaProxy; });
        ToggleTrafficLoggingCommand = new RelayCommand(() => { IsTrafficLoggingEnabled = !IsTrafficLoggingEnabled; });

        ToggleCloseToTrayCommand = new RelayCommand(() =>
        {
            CloseToTray = !CloseToTray;
            SaveCurrentProfileAsync();
        });

        ToggleStartWithWindowsCommand = new RelayCommand(() =>
        {
            StartWithWindows = !StartWithWindows;
            var settings = _settingsService.LoadSettings();
            settings.StartWithWindows = StartWithWindows;
            _settingsService.SaveSettings(settings);
            _settingsService.SetStartupWithWindows(StartWithWindows);
        });

        CloseDialogCommand = new RelayCommand(CloseDialogs);

        ClearConnectionsLogCommand = new RelayCommand(() =>
        {
            lock (_connectionLogLock)
            {
                _pendingConnectionLogs.Clear();
            }

            ConnectionsLog = null!;
            ConnectionsSearchText = null!;
            FilteredConnectionsLog = null!;

            ConnectionsLog = "";
            ConnectionsSearchText = "";
            FilteredConnectionsLog = "";

            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
        });

        ClearActivityLogCommand = new RelayCommand(() =>
        {
            lock (_activityLogLock)
            {
                _pendingActivityLogs.Clear();
            }

            ActivityLog = "";
            ActivitySearchText = "";
            FilteredActivityLog = "";

            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
        });

        SearchConnectionsCommand = new RelayCommand(() =>
        {
            FilteredConnectionsLog = FilterLog(_connectionsLog, _connectionsSearchText);
        });

        SearchActivityCommand = new RelayCommand(() =>
        {
            FilteredActivityLog = FilterLog(_activityLog, _activitySearchText);
        });

        AddRuleCommand = new RelayCommand(() =>
        {
            IsAddRuleViewOpen = true;
            NewProcessName = "";
            NewProxyAction = "PROXY";
        });

        SaveNewRuleCommand = new RelayCommand(() =>
        {
            if (string.IsNullOrWhiteSpace(NewProcessName))
                return;

            var rule = new ProxyRule
            {
                ProcessName = NewProcessName,
                TargetHosts = "*",
                TargetPorts = "*",
                Protocol = "TCP",
                Action = NewProxyAction,
                IsEnabled = true
            };

            if (_proxyService != null)
            {
                var ruleId = _proxyService.AddRule(NewProcessName, "*", "*", "TCP", NewProxyAction);
                if (ruleId > 0)
                {
                    rule.RuleId = ruleId;
                    ProxyRules.Add(rule);
                    SaveCurrentProfileAsync();
                    IsAddRuleViewOpen = false;
                    NewProcessName = "";
                }
                else
                {
                    QueueActivityLog("ERROR: Failed to add rule");
                }
            }
        });

        CancelAddRuleCommand = new RelayCommand(() =>
        {
            IsAddRuleViewOpen = false;
            NewProcessName = "";
        });

        NewProfileCommand = new RelayCommand(async () =>
        {
            if (_mainWindow == null) return;

            var dialog = new ProfileDialogWindow(
                "New Profile",
                "Enter a name for the new profile:",
                isInputMode: true,
                "New Profile");

            await dialog.ShowDialog(_mainWindow);

            if (!dialog.Confirmed) return;

            var name = dialog.InputValue;
            if (!ProfileManager.IsValidProfileName(name))
            {
                QueueActivityLog("Invalid profile name");
                return;
            }
            if (ProfileManager.ProfileExists(name))
            {
                QueueActivityLog($"Profile '{name}' already exists");
                return;
            }

            SaveCurrentProfile();
            ProfileManager.SaveProfile(name, new ProxyProfile { Name = name });
            SwitchToProfile(name);
            QueueActivityLog($"Profile created: {name}");
        });

        RenameProfileCommand = new RelayCommand(async () =>
        {
            if (_mainWindow == null) return;

            var dialog = new ProfileDialogWindow(
                "Rename Profile",
                "Enter a new name for the current profile:",
                isInputMode: true,
                _activeProfileName);

            await dialog.ShowDialog(_mainWindow);

            if (!dialog.Confirmed) return;

            var newName = dialog.InputValue;
            if (newName == _activeProfileName) return;

            if (!ProfileManager.IsValidProfileName(newName))
            {
                QueueActivityLog("Invalid profile name");
                return;
            }
            if (ProfileManager.ProfileExists(newName))
            {
                QueueActivityLog($"Profile '{newName}' already exists");
                return;
            }

            SaveCurrentProfile();

            if (ProfileManager.RenameProfile(_activeProfileName, newName))
            {
                _activeProfileName = newName;
                ActiveProfileName = newName;
                Title = $"ProxyBridge - {newName}";
                UpdateSettingsProfile(newName);
                RefreshProfileList();
                QueueActivityLog($"Profile renamed to: {newName}");
            }
        });

        DeleteProfileCommand = new RelayCommand(async () =>
        {
            if (_mainWindow == null) return;

            var profiles = ProfileManager.GetProfileNames();
            if (profiles.Length <= 1)
            {
                QueueActivityLog("Cannot delete the only profile");
                return;
            }

            var dialog = new ProfileDialogWindow(
                "Delete Profile",
                $"Delete profile '{_activeProfileName}'? This cannot be undone.",
                isInputMode: false);

            await dialog.ShowDialog(_mainWindow);

            if (!dialog.Confirmed) return;

            var nameToDelete = _activeProfileName;
            var nextProfile = profiles.FirstOrDefault(p => p != nameToDelete)
                ?? ProfileManager.DefaultProfileName;

            SwitchToProfile(nextProfile);
            ProfileManager.DeleteProfile(nameToDelete);
            RefreshProfileList();
            QueueActivityLog($"Profile deleted: {nameToDelete}");
        });

        ImportProfileCommand = new RelayCommand(async () =>
        {
            if (_mainWindow == null) return;
            var topLevel = TopLevel.GetTopLevel(_mainWindow);
            if (topLevel == null) return;

            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Import Profile",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("ProxyBridge Profile") { Patterns = new[] { "*.pbprofile" } },
                    new FilePickerFileType("All Files") { Patterns = new[] { "*.*" } }
                }
            });

            if (files.Count == 0) return;

            try
            {
                var localPath = files[0].TryGetLocalPath();
                if (string.IsNullOrEmpty(localPath))
                {
                    QueueActivityLog("Import failed: cannot access file");
                    return;
                }

                var importedName = ProfileManager.ImportProfile(localPath);
                if (importedName == null)
                {
                    QueueActivityLog("Import failed: invalid profile file");
                    return;
                }

                RefreshProfileList();
                QueueActivityLog($"Profile imported as: {importedName}");
            }
            catch (Exception ex)
            {
                QueueActivityLog($"Import failed: {ex.Message}");
            }
        });

        ExportProfileCommand = new RelayCommand(async () =>
        {
            if (_mainWindow == null) return;
            var topLevel = TopLevel.GetTopLevel(_mainWindow);
            if (topLevel == null) return;

            SaveCurrentProfile();

            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export Profile",
                SuggestedFileName = $"{_activeProfileName}.pbprofile",
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("ProxyBridge Profile") { Patterns = new[] { "*.pbprofile" } }
                }
            });

            if (file == null) return;

            try
            {
                var localPath = file.TryGetLocalPath();
                if (string.IsNullOrEmpty(localPath))
                {
                    QueueActivityLog("Export failed: cannot access path");
                    return;
                }

                if (ProfileManager.ExportProfile(_activeProfileName, localPath))
                    QueueActivityLog($"Profile exported: {_activeProfileName}");
                else
                    QueueActivityLog("Export failed");
            }
            catch (Exception ex)
            {
                QueueActivityLog($"Export failed: {ex.Message}");
            }
        });
    }

    public void ChangeLanguage(string languageCode)
    {
        if (string.IsNullOrEmpty(languageCode)) return;

        _currentLanguage = languageCode;
        EnglishCheckmark = languageCode == "en" ? "✓" : "";
        ChineseCheckmark = languageCode == "zh" ? "✓" : "";
        _loc.CurrentCulture = new System.Globalization.CultureInfo(languageCode);
        SaveCurrentProfileAsync();
    }

    private void CloseDialogs()
    {
        IsProxyRulesDialogOpen = false;
        IsProxySettingsDialogOpen = false;
    }

    private async Task CheckForUpdatesOnStartupAsync()
    {
        try
        {
            var settings = _settingsService.LoadSettings();
            if (!settings.CheckForUpdatesOnStartup)
                return;

            var updateService = new UpdateService();
            var versionInfo = await updateService.CheckForUpdatesAsync();

            if (versionInfo.IsUpdateAvailable && _mainWindow != null)
            {
                var notificationWindow = new UpdateNotificationWindow();
                var viewModel = new UpdateNotificationViewModel(() => notificationWindow.Close(), versionInfo);
                notificationWindow.DataContext = viewModel;
                _ = notificationWindow.ShowDialog(_mainWindow);
            }
        }
        catch { }
    }

    public void Cleanup()
    {
        try { SaveCurrentProfile(); } catch { }
        try { _proxyService?.Dispose(); _proxyService = null; } catch { }
    }

    private string FilterLog(string log, string searchText)
    {
        if (string.IsNullOrWhiteSpace(searchText))
            return log;

        var sb = new StringBuilder(log.Length / 2);
        var lines = log.Split('\n');

        foreach (var line in lines)
        {
            if (line.Contains(searchText, StringComparison.OrdinalIgnoreCase))
            {
                sb.Append(line);
                sb.Append('\n');
            }
        }

        return sb.ToString();
    }

    private void LoadConfiguration()
    {
        try
        {
            var settings = _settingsService.LoadSettings();
            StartWithWindows = settings.StartWithWindows && _settingsService.IsStartupEnabled();

            var profileName = settings.ActiveProfileName;
            if (!ProfileManager.ProfileExists(profileName))
                profileName = ProfileManager.DefaultProfileName;

            _activeProfileName = profileName;
            ActiveProfileName = profileName;
            Title = $"ProxyBridge - {profileName}";

            var profile = ProfileManager.LoadProfile(profileName);

            _dnsViaProxy = profile.DnsViaProxy;
            OnPropertyChanged(nameof(DnsViaProxy));

            _localhostViaProxy = profile.LocalhostViaProxy;
            OnPropertyChanged(nameof(LocalhostViaProxy));

            _closeToTray = profile.CloseToTray;
            OnPropertyChanged(nameof(CloseToTray));

            _isTrafficLoggingEnabled = profile.IsTrafficLoggingEnabled;
            OnPropertyChanged(nameof(IsTrafficLoggingEnabled));

            if (!string.IsNullOrWhiteSpace(profile.Language))
            {
                _currentLanguage = profile.Language;
                _loc.CurrentCulture = new System.Globalization.CultureInfo(profile.Language);
                EnglishCheckmark = profile.Language == "en" ? "✓" : "";
                ChineseCheckmark = profile.Language == "zh" ? "✓" : "";
            }

            if (profile.ProxyConfigs != null)
            {
                foreach (var pc in profile.ProxyConfigs)
                {
                    if (string.IsNullOrWhiteSpace(pc.Host)) continue;
                    ProxyConfigs.Add(new ProxyConfig
                    {
                        Id = pc.Id,
                        Type = pc.Type,
                        Host = pc.Host,
                        Port = pc.Port,
                        Username = pc.Username ?? "",
                        Password = pc.Password ?? ""
                    });
                }
            }

            if (profile.ProxyRules != null)
            {
                foreach (var rc in profile.ProxyRules)
                {
                    if (string.IsNullOrWhiteSpace(rc.ProcessName)) continue;
                    var pc = rc.ProxyConfigId > 0
                        ? ProxyConfigs.FirstOrDefault(p => p.Id == rc.ProxyConfigId)
                        : null;
                    ProxyRules.Add(new ProxyRule
                    {
                        ProcessName = rc.ProcessName,
                        TargetHosts = ValidationHelper.DefaultIfEmpty(rc.TargetHosts),
                        TargetPorts = ValidationHelper.DefaultIfEmpty(rc.TargetPorts),
                        Protocol = ValidationHelper.DefaultIfEmpty(rc.Protocol, "TCP"),
                        Action = ValidationHelper.DefaultIfEmpty(rc.Action, "PROXY"),
                        IsEnabled = rc.IsEnabled,
                        ProxyConfigId = rc.ProxyConfigId,
                        ProxyConfigDisplay = pc?.DisplayName ?? ""
                    });
                }
            }

            RefreshProfileList();
            QueueActivityLog("Configuration loaded");
        }
        catch (Exception ex)
        {
            QueueActivityLog($"Failed to load configuration: {ex.Message}");
        }
    }

    private void SwitchToProfile(string name)
    {
        foreach (var rule in ProxyRules.ToList())
            _proxyService?.DeleteRule(rule.RuleId);
        ProxyRules.Clear();

        foreach (var pc in ProxyConfigs.ToList())
            _proxyService?.DeleteProxyConfig(pc.Id);
        ProxyConfigs.Clear();

        var profile = ProfileManager.LoadProfile(name);
        _activeProfileName = name;
        ActiveProfileName = name;
        Title = $"ProxyBridge - {name}";

        _dnsViaProxy = profile.DnsViaProxy;
        OnPropertyChanged(nameof(DnsViaProxy));
        _proxyService?.SetDnsViaProxy(profile.DnsViaProxy);

        _localhostViaProxy = profile.LocalhostViaProxy;
        OnPropertyChanged(nameof(LocalhostViaProxy));
        _proxyService?.SetLocalhostViaProxy(profile.LocalhostViaProxy);

        _closeToTray = profile.CloseToTray;
        OnPropertyChanged(nameof(CloseToTray));

        if (profile.IsTrafficLoggingEnabled != _isTrafficLoggingEnabled)
        {
            _isTrafficLoggingEnabled = profile.IsTrafficLoggingEnabled;
            OnPropertyChanged(nameof(IsTrafficLoggingEnabled));
            ProxyBridgeService.SetTrafficLoggingEnabled(profile.IsTrafficLoggingEnabled);
        }

        if (!string.IsNullOrWhiteSpace(profile.Language))
        {
            _currentLanguage = profile.Language;
            _loc.CurrentCulture = new System.Globalization.CultureInfo(profile.Language);
            EnglishCheckmark = profile.Language == "en" ? "✓" : "";
            ChineseCheckmark = profile.Language == "zh" ? "✓" : "";
        }

        var configIdMap = new Dictionary<uint, uint>();
        foreach (var pc in profile.ProxyConfigs ?? new List<ProxyConfigEntry>())
        {
            if (string.IsNullOrWhiteSpace(pc.Host) || !ushort.TryParse(pc.Port, out ushort port)) continue;

            uint nativeId = _proxyService != null
                ? _proxyService.AddProxyConfig(pc.Type, pc.Host, port, pc.Username ?? "", pc.Password ?? "")
                : 0;

            uint assignedId = nativeId > 0 ? nativeId : pc.Id;
            if (pc.Id > 0) configIdMap[pc.Id] = assignedId;

            ProxyConfigs.Add(new ProxyConfig
            {
                Id = assignedId,
                Type = pc.Type,
                Host = pc.Host,
                Port = pc.Port,
                Username = pc.Username ?? "",
                Password = pc.Password ?? ""
            });
        }

        foreach (var rc in profile.ProxyRules ?? new List<ProxyRuleConfig>())
        {
            if (string.IsNullOrWhiteSpace(rc.ProcessName)) continue;

            uint nativeProxyId = 0;
            if (rc.ProxyConfigId > 0)
                configIdMap.TryGetValue(rc.ProxyConfigId, out nativeProxyId);

            var pcVm = nativeProxyId > 0 ? ProxyConfigs.FirstOrDefault(p => p.Id == nativeProxyId) : null;
            var rule = new ProxyRule
            {
                ProcessName = rc.ProcessName,
                TargetHosts = ValidationHelper.DefaultIfEmpty(rc.TargetHosts),
                TargetPorts = ValidationHelper.DefaultIfEmpty(rc.TargetPorts),
                Protocol = ValidationHelper.DefaultIfEmpty(rc.Protocol, "TCP"),
                Action = ValidationHelper.DefaultIfEmpty(rc.Action, "PROXY"),
                IsEnabled = rc.IsEnabled,
                ProxyConfigId = nativeProxyId,
                ProxyConfigDisplay = pcVm?.DisplayName ?? ""
            };

            if (_proxyService != null)
            {
                uint ruleId = _proxyService.AddRule(
                    rule.ProcessName, rule.TargetHosts, rule.TargetPorts,
                    rule.Protocol, rule.Action, nativeProxyId);
                if (ruleId > 0)
                {
                    rule.RuleId = ruleId;
                    rule.Index = ProxyRules.Count + 1;
                }
            }

            ProxyRules.Add(rule);
        }

        UpdateSettingsProfile(name);
        RefreshProfileList();
    }

    private void SaveCurrentProfile()
    {
        ProfileManager.SaveProfile(_activeProfileName, BuildCurrentProfile());
    }

    private void SaveCurrentProfileAsync()
    {
        var name = _activeProfileName;
        var profile = BuildCurrentProfile();
        Task.Run(() => ProfileManager.SaveProfile(name, profile));
    }

    private ProxyProfile BuildCurrentProfile()
    {
        return new ProxyProfile
        {
            DnsViaProxy = _dnsViaProxy,
            LocalhostViaProxy = _localhostViaProxy,
            IsTrafficLoggingEnabled = _isTrafficLoggingEnabled,
            Language = _currentLanguage,
            CloseToTray = _closeToTray,
            ProxyConfigs = ProxyConfigs.Select(pc => new ProxyConfigEntry
            {
                Id = pc.Id,
                Type = pc.Type,
                Host = pc.Host,
                Port = pc.Port,
                Username = pc.Username,
                Password = pc.Password
            }).ToList(),
            ProxyRules = ProxyRules.Select(r => new ProxyRuleConfig
            {
                ProcessName = r.ProcessName,
                TargetHosts = r.TargetHosts,
                TargetPorts = r.TargetPorts,
                Protocol = r.Protocol,
                Action = r.Action,
                IsEnabled = r.IsEnabled,
                ProxyConfigId = r.ProxyConfigId
            }).ToList()
        };
    }

    private void RefreshProfileList()
    {
        SwitchProfileItems.Clear();
        foreach (var name in ProfileManager.GetProfileNames())
            SwitchProfileItems.Add(name);
    }

    private void UpdateSettingsProfile(string name)
    {
        var settings = _settingsService.LoadSettings();
        settings.ActiveProfileName = name;
        _settingsService.SaveSettings(settings);
    }

    private void QueueActivityLog(string message)
    {
        lock (_activityLogLock)
            _pendingActivityLogs.Add($"[{DateTime.Now:HH:mm:ss}] {message}\n");
    }
}

public class ProxyRule : ViewModelBase
{
    private string _processName = "*";
    private string _targetHosts = "*";
    private string _targetPorts = "*";
    private string _protocol = "TCP";
    private string _action = "PROXY";
    private bool _isEnabled = true;
    private bool _isSelected = false;
    private int _index;
    private uint _ruleId;

    public int Index
    {
        get => _index;
        set => SetProperty(ref _index, value);
    }

    public uint RuleId
    {
        get => _ruleId;
        set => SetProperty(ref _ruleId, value);
    }

    public string ProcessName
    {
        get => _processName;
        set => SetProperty(ref _processName, value);
    }

    public string TargetHosts
    {
        get => _targetHosts;
        set => SetProperty(ref _targetHosts, value);
    }

    public string TargetPorts
    {
        get => _targetPorts;
        set => SetProperty(ref _targetPorts, value);
    }

    public string Protocol
    {
        get => _protocol;
        set => SetProperty(ref _protocol, value);
    }

    public string Action
    {
        get => _action;
        set
        {
            if (SetProperty(ref _action, value))
                OnPropertyChanged(nameof(ActionDisplay));
        }
    }

    private uint _proxyConfigId;
    public uint ProxyConfigId
    {
        get => _proxyConfigId;
        set => SetProperty(ref _proxyConfigId, value);
    }

    private string _proxyConfigDisplay = "";
    public string ProxyConfigDisplay
    {
        get => _proxyConfigDisplay;
        set => SetProperty(ref _proxyConfigDisplay, value);
    }

    public string ActionDisplay => Action == "PROXY"
        ? (string.IsNullOrEmpty(_proxyConfigDisplay) ? "PROXY" : _proxyConfigDisplay)
        : Action;

    public bool IsEnabled
    {
        get => _isEnabled;
        set => SetProperty(ref _isEnabled, value);
    }

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}

public class ProxyConfig : ViewModelBase
{
    private uint _id;
    private string _type = "SOCKS5";
    private string _host = "";
    private string _port = "";
    private string _username = "";
    private string _password = "";

    public uint Id
    {
        get => _id;
        set => SetProperty(ref _id, value);
    }

    public string Type
    {
        get => _type;
        set
        {
            if (SetProperty(ref _type, value))
                OnPropertyChanged(nameof(DisplayName));
        }
    }

    public string Host
    {
        get => _host;
        set
        {
            if (SetProperty(ref _host, value))
                OnPropertyChanged(nameof(DisplayName));
        }
    }

    public string Port
    {
        get => _port;
        set
        {
            if (SetProperty(ref _port, value))
                OnPropertyChanged(nameof(DisplayName));
        }
    }

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public string Password
    {
        get => _password;
        set => SetProperty(ref _password, value);
    }

    public string DisplayName => $"{_type} {_host}:{_port}";
}

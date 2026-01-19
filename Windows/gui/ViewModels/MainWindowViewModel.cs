using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Threading;
using Avalonia.Controls;
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
    private string _activityLog = "ProxyBridge initialized successfully\n";
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
    private readonly SettingsService _settingsService = new SettingsService();

    private string _currentProxyType = "SOCKS5";
    private string _currentProxyIp = "";
    private string _currentProxyPort = "";
    private string _currentProxyUsername = "";
    private string _currentProxyPassword = "";

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
                {
                    _pendingActivityLogs.Add($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
                }
            };

            _proxyService.ConnectionReceived += (processName, pid, destIp, destPort, proxyInfo) =>
            {
                if (!_isTrafficLoggingEnabled)
                    return;

                string logEntry = $"[{DateTime.Now:HH:mm:ss}] {processName} (PID:{pid}) -> {destIp}:{destPort} via {proxyInfo}\n";
                lock (_connectionLogLock)
                {
                    _pendingConnectionLogs.Add(logEntry);
                }
            };

            // Timer to flush batched logs to UI every 500ms
            _connectionLogTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
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
                {
                    var linesToKeep = lines.Skip(lines.Length - MAX_CONNECTION_LOG_LINES).ToArray();
                    ConnectionsLog = string.Join("\n", linesToKeep);
                }
            };
            if (_isTrafficLoggingEnabled)
            {
                _connectionLogTimer.Start();
            }

            _activityLogTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
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

            // Apply config DNS setting
            _proxyService.SetDnsViaProxy(_dnsViaProxy);

            // Apply comfig proxy settings
            if (!string.IsNullOrEmpty(_currentProxyIp) &&
                !string.IsNullOrEmpty(_currentProxyPort) &&
                ushort.TryParse(_currentProxyPort, out ushort portNum))
            {
                _proxyService.SetProxyConfig(
                    _currentProxyType,
                    _currentProxyIp,
                    portNum,
                    _currentProxyUsername,
                    _currentProxyPassword);

                QueueActivityLog($"Restored proxy settings: {_currentProxyType} {_currentProxyIp}:{_currentProxyPort}");
            }

            // Start the proxy bridge
            if (_proxyService.Start())
            {
                QueueActivityLog("ProxyBridge service started successfully");

                // Apply config proxy rules, Need to see if this cause UI issues/slow/freeze
                foreach (var rule in ProxyRules)
                {
                    uint ruleId = _proxyService.AddRule(
                        rule.ProcessName,
                        rule.TargetHosts,
                        rule.TargetPorts,
                        rule.Protocol,
                        rule.Action);

                    if (ruleId > 0)
                    {
                        rule.RuleId = ruleId;
                        rule.Index = ProxyRules.IndexOf(rule) + 1;
                    }
                }

                if (ProxyRules.Count > 0)
                {
                    QueueActivityLog($"Restored {ProxyRules.Count} proxy rule(s)");
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

    public ObservableCollection<ProxyRule> ProxyRules { get; } = new();

    private bool _dnsViaProxy = true;  // Default TRUE
    public bool DnsViaProxy
    {
        get => _dnsViaProxy;
        set
        {
            if (SetProperty(ref _dnsViaProxy, value))
            {
                _proxyService?.SetDnsViaProxy(value);
                SaveConfigurationInternal();
                QueueActivityLog($"DNS via Proxy: {(value ? "Enabled" : "Disabled")}");
            }
        }
    }

    private bool _isTrafficLoggingEnabled = true;  // Default TRUE
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
                    // Clear pending logs when disabled
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
                SaveConfigurationInternal();
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

    // Commands
    public ICommand ShowProxySettingsCommand { get; }
    public ICommand ShowProxyRulesCommand { get; }
    public ICommand ShowAboutCommand { get; }
    public ICommand CheckForUpdatesCommand { get; }
    public ICommand ToggleDnsViaProxyCommand { get; }
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

    public MainWindowViewModel()
    {
        ShowProxySettingsCommand = new RelayCommand(async () =>
        {
            var window = new ProxySettingsWindow();

            var viewModel = new ProxySettingsViewModel(
                initialType: _currentProxyType,
                initialIp: _currentProxyIp,
                initialPort: _currentProxyPort,
                initialUsername: _currentProxyUsername,
                initialPassword: _currentProxyPassword,
                onSave: (type, ip, port, username, password) =>
                {
                    if (_proxyService != null && ushort.TryParse(port, out ushort portNum))
                    {
                        if (_proxyService.SetProxyConfig(type, ip, portNum, username, password))
                        {

                            _currentProxyType = type;
                            _currentProxyIp = ip;
                            _currentProxyPort = port;
                            _currentProxyUsername = username;
                            _currentProxyPassword = password;

                            SaveConfigurationInternal();
                            string authInfo = string.IsNullOrEmpty(username) ? "" : " (with auth)";
                            QueueActivityLog($"Saved proxy settings: {type} {ip}:{port}{authInfo}");
                        }
                        else
                        {
                            QueueActivityLog("ERROR: Failed to set proxy config");
                        }
                    }
                    window.Close();
                },
                onClose: () =>
                {
                    window.Close();
                },
                proxyService: _proxyService
            );

            window.DataContext = viewModel;

            if (_mainWindow != null)
            {
                await window.ShowDialog(_mainWindow);
            }
        });

        ShowProxyRulesCommand = new RelayCommand(async () =>
        {
            var window = new ProxyRulesWindow();

            var viewModel = new ProxyRulesViewModel(
                proxyRules: ProxyRules,
                onAddRule: (rule) =>
                {
                    if (_proxyService != null)
                    {
                        uint ruleId = _proxyService.AddRule(
                            rule.ProcessName,
                            rule.TargetHosts,
                            rule.TargetPorts,
                            rule.Protocol,
                            rule.Action);
                        if (ruleId > 0)
                        {
                            rule.RuleId = ruleId;
                            rule.Index = ProxyRules.Count + 1;
                            ProxyRules.Add(rule);
                            SaveConfigurationInternal();
                            QueueActivityLog($"Added rule: {rule.ProcessName} ({rule.TargetHosts}:{rule.TargetPorts} {rule.Protocol}) -> {rule.Action} (ID: {ruleId})");
                        }
                        else
                        {
                            QueueActivityLog("ERROR: Failed to add rule");
                        }
                    }
                },
                onClose: () =>
                {
                    window.Close();
                },
                proxyService: _proxyService,
                onConfigChanged: SaveConfigurationInternal
            );

            window.DataContext = viewModel;
            viewModel.SetWindow(window);

            if (_mainWindow != null)
            {
                await window.ShowDialog(_mainWindow);
            }
        });

        ShowAboutCommand = new RelayCommand(async () =>
        {
            var viewModel = new AboutViewModel(() =>
            {
                // Window will be closed
            });

            var window = new Views.AboutWindow
            {
                DataContext = viewModel
            };

            if (_mainWindow != null)
            {
                await window.ShowDialog(_mainWindow);
            }
        });

        CheckForUpdatesCommand = new RelayCommand(async () =>
        {
            var updateWindow = new UpdateCheckWindow();
            var viewModel = new UpdateCheckViewModel(() => updateWindow.Close());
            updateWindow.DataContext = viewModel;

            if (_mainWindow != null)
            {
                await updateWindow.ShowDialog(_mainWindow);
            }
        });

        ToggleDnsViaProxyCommand = new RelayCommand(() =>
        {
            DnsViaProxy = !DnsViaProxy;
        });

        ToggleTrafficLoggingCommand = new RelayCommand(() =>
        {
            IsTrafficLoggingEnabled = !IsTrafficLoggingEnabled;
        });

        ToggleCloseToTrayCommand = new RelayCommand(() =>
        {
            CloseToTray = !CloseToTray;
            SaveConfigurationInternal();
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
            var oldActivity = ActivityLog;
            var oldSearch = ActivitySearchText;
            var oldFiltered = FilteredActivityLog;

            ActivityLog = "ProxyBridge initialized successfully\n";
            ActivitySearchText = "";
            FilteredActivityLog = "ProxyBridge initialized successfully\n";

            oldActivity = null!;
            oldSearch = null!;
            oldFiltered = null!;

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
            {
                return;
            }

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
                    SaveConfigurationInternal();
                    QueueActivityLog($"Added rule: {NewProcessName} -> {NewProxyAction}");
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
    }

    public void ChangeLanguage(string languageCode)
    {
        if (string.IsNullOrEmpty(languageCode)) return;

        _currentLanguage = languageCode;
        EnglishCheckmark = languageCode == "en" ? "✓" : "";
        ChineseCheckmark = languageCode == "zh" ? "✓" : "";

        var config = ConfigManager.LoadConfig();
        config.Language = languageCode;
        ConfigManager.SaveConfig(config);

        _loc.CurrentCulture = new System.Globalization.CultureInfo(languageCode);

        QueueActivityLog($"{_loc.LogLanguageChanged}: {languageCode}");
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
            var settingsService = new SettingsService();
            var settings = settingsService.LoadSettings();
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
        catch
        {
            // silently fail
        }
    }

    public void Cleanup()
    {
        // this something can be improved maybe config doesnt need save during cleanup
        try { SaveConfigurationInternal(); } catch { }

        try { _proxyService?.Dispose(); _proxyService = null; }
        catch { }
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

            var config = ConfigManager.LoadConfig();

            _currentProxyType = config.ProxyType;
            _currentProxyIp = config.ProxyIp;
            _currentProxyPort = config.ProxyPort;
            _currentProxyUsername = config.ProxyUsername;
            _currentProxyPassword = config.ProxyPassword;

            DnsViaProxy = config.DnsViaProxy;
            CloseToTray = config.CloseToTray;
            IsTrafficLoggingEnabled = config.IsTrafficLoggingEnabled;

            _currentLanguage = config.Language;
            _loc.CurrentCulture = new System.Globalization.CultureInfo(config.Language);
            EnglishCheckmark = config.Language == "en" ? "✓" : "";
            ChineseCheckmark = config.Language == "zh" ? "✓" : "";

            foreach (var ruleConfig in config.ProxyRules)
            {
                var rule = new ProxyRule
                {
                    ProcessName = ruleConfig.ProcessName,
                    TargetHosts = ruleConfig.TargetHosts,
                    TargetPorts = ruleConfig.TargetPorts,
                    Protocol = ruleConfig.Protocol,
                    Action = ruleConfig.Action,
                    IsEnabled = ruleConfig.IsEnabled
                };
                ProxyRules.Add(rule);
            }
        }
        catch (Exception ex)
        {
            QueueActivityLog($"Failed to load configuration: {ex.Message}");
        }
    }

    private void SaveConfigurationInternal()
    {
        Task.Run(() => SaveConfigurationInternalAsync());
    }

    private void SaveConfigurationInternalAsync()
    {
        try
        {
            var config = new AppConfig
            {
                ProxyType = _currentProxyType,
                ProxyIp = _currentProxyIp,
                ProxyPort = _currentProxyPort,
                ProxyUsername = _currentProxyUsername,
                ProxyPassword = _currentProxyPassword,
                DnsViaProxy = _dnsViaProxy,
                IsTrafficLoggingEnabled = _isTrafficLoggingEnabled,
                Language = _currentLanguage,
                CloseToTray = _closeToTray,
                ProxyRules = ProxyRules.Select(r => new ProxyRuleConfig
                {
                    ProcessName = r.ProcessName,
                    TargetHosts = r.TargetHosts,
                    TargetPorts = r.TargetPorts,
                    Protocol = r.Protocol,
                    Action = r.Action,
                    IsEnabled = r.IsEnabled
                }).ToList()
            };

            ConfigManager.SaveConfig(config);
        }
        catch { }
    }

    private void QueueActivityLog(string message)
    {
        lock (_activityLogLock)
        {
            _pendingActivityLogs.Add($"[{DateTime.Now:HH:mm:ss}] {message}\n");
        }
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
        set => SetProperty(ref _action, value);
    }

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

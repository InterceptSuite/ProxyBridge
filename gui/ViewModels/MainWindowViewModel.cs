using System;
using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Linq;
using Avalonia.Threading;
using Avalonia.Controls;
using ProxyBridge.GUI.Views;
using ProxyBridge.GUI.Services;

namespace ProxyBridge.GUI.ViewModels;

public class MainWindowViewModel : ViewModelBase
{
    private string _title = "ProxyBridge v1.1";
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
    private Window? _mainWindow;
    private ProxyBridgeService? _proxyService;

    public void SetMainWindow(Window window)
    {
        _mainWindow = window;

        try
        {
            _proxyService = new ProxyBridgeService();
            _proxyService.LogReceived += (msg) =>
            {
                Dispatcher.UIThread.Post(() =>
                {
                    ActivityLog += $"[{DateTime.Now:HH:mm:ss}] {msg}\n";
                });
            };

            _proxyService.ConnectionReceived += (processName, pid, destIp, destPort, proxyInfo) =>
            {
                Dispatcher.UIThread.Post(() =>
                {
                    ConnectionsLog += $"[{DateTime.Now:HH:mm:ss}] {processName} (PID:{pid}) -> {destIp}:{destPort} via {proxyInfo}\n";
                });
            };

            // Start the proxy bridge
            if (_proxyService.Start())
            {
                ActivityLog += $"[{DateTime.Now:HH:mm:ss}] ProxyBridge service started successfully\n";
            }
            else
            {
                ActivityLog += $"[{DateTime.Now:HH:mm:ss}] ERROR: Failed to start ProxyBridge service\n";
            }
        }
        catch (Exception ex)
        {
            ActivityLog += $"[{DateTime.Now:HH:mm:ss}] ERROR: {ex.Message}\n";
        }
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
            SetProperty(ref _connectionsLog, value);
            FilterConnectionsLog();
        }
    }

    public string ActivityLog
    {
        get => _activityLog;
        set
        {
            SetProperty(ref _activityLog, value);
            FilterActivityLog();
        }
    }

    public string ConnectionsSearchText
    {
        get => _connectionsSearchText;
        set
        {
            SetProperty(ref _connectionsSearchText, value);
            FilterConnectionsLog();
        }
    }

    public string ActivitySearchText
    {
        get => _activitySearchText;
        set
        {
            SetProperty(ref _activitySearchText, value);
            FilterActivityLog();
        }
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

    // Commands
    public ICommand ShowProxySettingsCommand { get; }
    public ICommand ShowProxyRulesCommand { get; }
    public ICommand ShowAboutCommand { get; }
    public ICommand CloseDialogCommand { get; }
    public ICommand ClearConnectionsLogCommand { get; }
    public ICommand ClearActivityLogCommand { get; }
    public ICommand AddRuleCommand { get; }
    public ICommand SaveNewRuleCommand { get; }
    public ICommand CancelAddRuleCommand { get; }

    public MainWindowViewModel()
    {
        ShowProxySettingsCommand = new RelayCommand(async () =>
        {
            var window = new ProxySettingsWindow();

            var viewModel = new ProxySettingsViewModel(
                onSave: (type, ip, port) =>
                {
                    if (_proxyService != null && ushort.TryParse(port, out ushort portNum))
                    {
                        if (_proxyService.SetProxyConfig(type, ip, portNum))
                        {
                            ActivityLog += $"[{DateTime.Now:HH:mm:ss}] Saved proxy settings: {type} {ip}:{port}\n";
                        }
                        else
                        {
                            ActivityLog += $"[{DateTime.Now:HH:mm:ss}] ERROR: Failed to set proxy config\n";
                        }
                    }
                    window.Close();
                },
                onClose: () =>
                {
                    window.Close();
                }
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
                        uint ruleId = _proxyService.AddRule(rule.ProcessName, rule.Action);
                        if (ruleId > 0)
                        {
                            rule.RuleId = ruleId;
                            rule.Index = ProxyRules.Count + 1;
                            ProxyRules.Add(rule);
                            ActivityLog += $"[{DateTime.Now:HH:mm:ss}] Added rule: {rule.ProcessName} -> {rule.Action} (ID: {ruleId})\n";
                        }
                        else
                        {
                            ActivityLog += $"[{DateTime.Now:HH:mm:ss}] ERROR: Failed to add rule\n";
                        }
                    }
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

        CloseDialogCommand = new RelayCommand(CloseDialogs);

        ClearConnectionsLogCommand = new RelayCommand(() =>
        {
            ConnectionsLog = "";
        });

        ClearActivityLogCommand = new RelayCommand(() =>
        {
            ActivityLog = "ProxyBridge initialized successfully\n";
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
                Action = NewProxyAction,
                IsEnabled = true
            };

            if (_proxyService != null)
            {
                var ruleId = _proxyService.AddRule(NewProcessName, NewProxyAction);
                if (ruleId > 0)
                {
                    rule.RuleId = ruleId;
                    ProxyRules.Add(rule);
                    ActivityLog += $"[{DateTime.Now:HH:mm:ss}] Added rule: {NewProcessName} -> {NewProxyAction}\n";
                    IsAddRuleViewOpen = false;
                    NewProcessName = "";
                }
                else
                {
                    ActivityLog += $"[{DateTime.Now:HH:mm:ss}] ERROR: Failed to add rule\n";
                }
            }
        });

        CancelAddRuleCommand = new RelayCommand(() =>
        {
            IsAddRuleViewOpen = false;
            NewProcessName = "";
        });
    }

    private void FilterConnectionsLog()
    {
        if (string.IsNullOrWhiteSpace(_connectionsSearchText))
        {
            FilteredConnectionsLog = _connectionsLog;
        }
        else
        {
            var lines = _connectionsLog.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var filtered = lines.Where(line => line.Contains(_connectionsSearchText, StringComparison.OrdinalIgnoreCase));
            FilteredConnectionsLog = string.Join('\n', filtered) + (filtered.Any() ? "\n" : "");
        }
    }

    private void FilterActivityLog()
    {
        if (string.IsNullOrWhiteSpace(_activitySearchText))
        {
            FilteredActivityLog = _activityLog;
        }
        else
        {
            var lines = _activityLog.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var filtered = lines.Where(line => line.Contains(_activitySearchText, StringComparison.OrdinalIgnoreCase));
            FilteredActivityLog = string.Join('\n', filtered) + (filtered.Any() ? "\n" : "");
        }
    }

    private void CloseDialogs()
    {
        IsProxyRulesDialogOpen = false;
        IsProxySettingsDialogOpen = false;
    }

    public void Cleanup()
    {
        _proxyService?.Dispose();
        _proxyService = null;
    }
}

public class ProxyRule : ViewModelBase
{
    private string _processName = "";
    private string _action = "PROXY";
    private bool _isEnabled = true;
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
}

// Simple ICommand implementation
public class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;

    public void Execute(object? parameter) => _execute();

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

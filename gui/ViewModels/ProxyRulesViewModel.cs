using System;
using System.Collections.ObjectModel;
using System.Windows.Input;
using Avalonia.Controls;
using ProxyBridge.GUI.Services;

namespace ProxyBridge.GUI.ViewModels;

public class ProxyRulesViewModel : ViewModelBase
{
    private bool _isAddRuleViewOpen;
    private string _newProcessName = "*";
    private string _newTargetHosts = "*";
    private string _newTargetPorts = "*";
    private string _newProtocol = "TCP"; // TCP, UDP, or BOTH
    private string _newProxyAction = "PROXY";
    private string _processNameError = "";
    private Action<ProxyRule>? _onAddRule;
    private Action? _onClose;
    private ProxyBridgeService? _proxyService;
    private Window? _window;

    public ObservableCollection<ProxyRule> ProxyRules { get; }

    public bool IsAddRuleViewOpen
    {
        get => _isAddRuleViewOpen;
        set => SetProperty(ref _isAddRuleViewOpen, value);
    }

    public string NewProcessName
    {
        get => _newProcessName;
        set
        {
            SetProperty(ref _newProcessName, value);
            ProcessNameError = "";
        }
    }

    public string NewTargetHosts
    {
        get => _newTargetHosts;
        set => SetProperty(ref _newTargetHosts, value);
    }

    public string NewTargetPorts
    {
        get => _newTargetPorts;
        set => SetProperty(ref _newTargetPorts, value);
    }

    public string NewProtocol
    {
        get => _newProtocol;
        set => SetProperty(ref _newProtocol, value);
    }

    public string NewProxyAction
    {
        get => _newProxyAction;
        set => SetProperty(ref _newProxyAction, value);
    }

    public string ProcessNameError
    {
        get => _processNameError;
        set => SetProperty(ref _processNameError, value);
    }

    public ICommand AddRuleCommand { get; }
    public ICommand SaveNewRuleCommand { get; }
    public ICommand CancelAddRuleCommand { get; }
    public ICommand CloseCommand { get; }
    public ICommand BrowseProcessCommand { get; }

    public void SetWindow(Window window)
    {
        _window = window;
    }

    public ProxyRulesViewModel(ObservableCollection<ProxyRule> proxyRules, Action<ProxyRule> onAddRule, Action onClose, ProxyBridgeService? proxyService = null)
    {
        ProxyRules = proxyRules;
        _onAddRule = onAddRule;
        _onClose = onClose;
        _proxyService = proxyService;

        foreach (var rule in ProxyRules)
        {
            rule.PropertyChanged += Rule_PropertyChanged;
        }

        AddRuleCommand = new RelayCommand(() =>
        {
            IsAddRuleViewOpen = true;
        });

        SaveNewRuleCommand = new RelayCommand(() =>
        {
            // Use "*" if empty
            if (string.IsNullOrWhiteSpace(NewProcessName))
            {
                NewProcessName = "*";
            }

            if (string.IsNullOrWhiteSpace(NewTargetHosts))
            {
                NewTargetHosts = "*";
            }

            if (string.IsNullOrWhiteSpace(NewTargetPorts))
            {
                NewTargetPorts = "*";
            }

            // This could be an issue if app name contain char
            if (!System.Text.RegularExpressions.Regex.IsMatch(NewProcessName, @"^[a-zA-Z0-9\s._\-*;""\\:]+$"))
            {
                ProcessNameError = "Invalid characters in process name. Only letters, numbers, spaces, dots, dashes, underscores, semicolons, quotes, and * are allowed";
                return;
            }

            if (NewProcessName != "*" && !NewProcessName.Equals("*", StringComparison.OrdinalIgnoreCase))
            {
                if (!NewProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !NewProcessName.Contains(".exe ", StringComparison.OrdinalIgnoreCase) &&
                    !NewProcessName.Contains(";", StringComparison.OrdinalIgnoreCase))
                {
                    NewProcessName += ".exe";
                }
            }

            var newRule = new ProxyRule
            {
                ProcessName = NewProcessName,
                TargetHosts = NewTargetHosts,
                TargetPorts = NewTargetPorts,
                Protocol = NewProtocol,
                Action = NewProxyAction,
                IsEnabled = true
            };

            newRule.PropertyChanged += Rule_PropertyChanged;

            _onAddRule?.Invoke(newRule);

            // Reset to defaults
            NewProcessName = "*";
            NewTargetHosts = "*";
            NewTargetPorts = "*";
            NewProtocol = "TCP";
            NewProxyAction = "PROXY";
            ProcessNameError = "";
            IsAddRuleViewOpen = false;
        });        CancelAddRuleCommand = new RelayCommand(() =>
        {
            NewProcessName = "*";
            NewTargetHosts = "*";
            NewTargetPorts = "*";
            NewProtocol = "TCP";
            NewProxyAction = "PROXY";
            ProcessNameError = "";
            IsAddRuleViewOpen = false;
        });

        CloseCommand = new RelayCommand(() =>
        {
            _onClose?.Invoke();
        });

        BrowseProcessCommand = new RelayCommand(async () =>
        {
            if (_window == null)
                return;

            var dialog = new Avalonia.Platform.Storage.FilePickerOpenOptions
            {
                Title = "Select Process Executable",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new Avalonia.Platform.Storage.FilePickerFileType("Executable Files")
                    {
                        Patterns = new[] { "*.exe" }
                    },
                    new Avalonia.Platform.Storage.FilePickerFileType("All Files")
                    {
                        Patterns = new[] { "*.*" }
                    }
                }
            };

            var result = await _window.StorageProvider.OpenFilePickerAsync(dialog);

            if (result != null && result.Count > 0)
            {
                string filename = System.IO.Path.GetFileName(result[0].Path.LocalPath);
                if (string.IsNullOrWhiteSpace(NewProcessName) || NewProcessName == "*")
                {
                    NewProcessName = filename;
                }
                else
                {
                    if (!NewProcessName.EndsWith(";"))
                        NewProcessName += "; ";
                    else
                        NewProcessName += " ";

                    NewProcessName += filename;
                }
            }
        });
    }

    private void Rule_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ProxyRule.IsEnabled) && sender is ProxyRule rule && _proxyService != null)
        {
            if (rule.IsEnabled)
            {
                _proxyService.EnableRule(rule.RuleId);
            }
            else
            {
                _proxyService.DisableRule(rule.RuleId);
            }
        }
    }
}

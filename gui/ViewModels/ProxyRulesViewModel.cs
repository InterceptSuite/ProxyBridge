using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using Avalonia.Controls;
using ProxyBridge.GUI.Services;

namespace ProxyBridge.GUI.ViewModels;

public class ProxyRulesViewModel : ViewModelBase
{
    private readonly Loc _loc = Loc.Instance;
    public Loc Loc => _loc;

    private bool _isAddRuleViewOpen;
    private bool _isEditMode;
    private uint _currentEditingRuleId;
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
    public ICommand DeleteRuleCommand { get; }
    public ICommand EditRuleCommand { get; }

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
            NewProcessName = "*";
            NewTargetHosts = "*";
            NewTargetPorts = "*";
            NewProtocol = "TCP";
            NewProxyAction = "PROXY";
            ProcessNameError = "";
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

            if (_isEditMode && _proxyService != null)
            {
                // Edit existing rule
                if (_proxyService.EditRule(_currentEditingRuleId, NewProcessName, NewTargetHosts, NewTargetPorts, NewProtocol, NewProxyAction))
                {
                    // Update the rule in the ObservableCollection
                    var existingRule = ProxyRules.FirstOrDefault(r => r.RuleId == _currentEditingRuleId);
                    if (existingRule != null)
                    {
                        existingRule.ProcessName = NewProcessName;
                        existingRule.TargetHosts = NewTargetHosts;
                        existingRule.TargetPorts = NewTargetPorts;
                        existingRule.Protocol = NewProtocol;
                        existingRule.Action = NewProxyAction;
                    }
                }

                _isEditMode = false;
                _currentEditingRuleId = 0;
            }
            else
            {
                // Add new rule
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
            }

            IsAddRuleViewOpen = false;

            // Reset to defaults
            NewProcessName = "*";
            NewTargetHosts = "*";
            NewTargetPorts = "*";
            NewProtocol = "TCP";
            NewProxyAction = "PROXY";
            ProcessNameError = "";
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

        DeleteRuleCommand = new RelayCommandWithParameter<ProxyRule>(async (rule) =>
        {
            if (rule == null || _proxyService == null || _window == null)
                return;

            var result = await ShowConfirmDialogAsync("Delete Rule",
                $"Are you sure you want to delete the rule for process '{rule.ProcessName}'?");

            if (result)
            {
                if (_proxyService.DeleteRule(rule.RuleId))
                {
                    ProxyRules.Remove(rule);
                }
            }
        });

        EditRuleCommand = new RelayCommandWithParameter<ProxyRule>((rule) =>
        {
            if (rule == null)
                return;

            _isEditMode = true;
            _currentEditingRuleId = rule.RuleId;
            NewProcessName = rule.ProcessName;
            NewTargetHosts = rule.TargetHosts;
            NewTargetPorts = rule.TargetPorts;
            NewProtocol = rule.Protocol;
            NewProxyAction = rule.Action;
            ProcessNameError = "";
            IsAddRuleViewOpen = true;
        });
    }

    private async System.Threading.Tasks.Task<bool> ShowConfirmDialogAsync(string title, string message)
    {
        if (_window == null)
            return false;

        var messageBox = new Window
        {
            Title = title,
            Width = 400,
            Height = 150,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false
        };

        bool result = false;

        var stackPanel = new StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 10
        };

        stackPanel.Children.Add(new Avalonia.Controls.TextBlock
        {
            Text = message,
            TextWrapping = Avalonia.Media.TextWrapping.Wrap
        });

        var buttonPanel = new StackPanel
        {
            Orientation = Avalonia.Layout.Orientation.Horizontal,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
            Spacing = 10
        };

        var yesButton = new Button
        {
            Content = "Yes",
            Width = 80
        };
        yesButton.Click += (s, e) =>
        {
            result = true;
            messageBox.Close();
        };

        var noButton = new Button
        {
            Content = "No",
            Width = 80
        };
        noButton.Click += (s, e) =>
        {
            result = false;
            messageBox.Close();
        };

        buttonPanel.Children.Add(yesButton);
        buttonPanel.Children.Add(noButton);
        stackPanel.Children.Add(buttonPanel);

        messageBox.Content = stackPanel;

        await messageBox.ShowDialog(_window);
        return result;
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

public class RelayCommandWithParameter<T> : ICommand
{
    private readonly Action<T> _execute;
    private readonly Func<T, bool>? _canExecute;

    public RelayCommandWithParameter(Action<T> execute, Func<T, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter)
    {
        if (parameter is T typedParameter)
            return _canExecute?.Invoke(typedParameter) ?? true;
        return false;
    }

    public void Execute(object? parameter)
    {
        if (parameter is T typedParameter)
            _execute(typedParameter);
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using Avalonia.Controls;
using ProxyBridge.GUI.Services;
using ProxyBridge.GUI.Common;

namespace ProxyBridge.GUI.ViewModels;

public class ProxyRulesViewModel : ViewModelBase
{
    private static readonly System.Text.RegularExpressions.Regex _processNameRegex =
        new(@"^[\w\s._\-*;""\\:()\u4E00-\u9FFF\u3400-\u4DBF\uF900-\uFAFF]+$",
            System.Text.RegularExpressions.RegexOptions.Compiled);

    private readonly Loc _loc = Loc.Instance;
    public Loc Loc => _loc;

    private bool _isAddRuleViewOpen;
    private bool _isEditMode;
    private uint _currentEditingRuleId;
    private string _newProcessName = "*";
    private string _newTargetHosts = "*";
    private string _newTargetPorts = "*";
    private string _newProtocol = "TCP"; // TCP, UDP, or BOTH
    private RuleActionItem? _selectedRuleAction;
    private string _processNameError = "";
    private Action<ProxyRule>? _onAddRule;
    private Action? _onClose;
    private Action? _onConfigChanged;
    private ProxyBridgeService? _proxyService;
    private Window? _window;

    public ObservableCollection<ProxyRule> ProxyRules { get; }
    public ObservableCollection<RuleActionItem> AvailableActions { get; } = new();

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

    public RuleActionItem? SelectedRuleAction
    {
        get => _selectedRuleAction;
        set => SetProperty(ref _selectedRuleAction, value);
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
    public ICommand ToggleSelectAllCommand { get; }
    public ICommand DeleteSelectedRulesCommand { get; }

    public bool HasSelectedRules => ProxyRules.Any(r => r.IsSelected);
    public bool AllRulesSelected => ProxyRules.Any() && ProxyRules.All(r => r.IsSelected);

    public void SetWindow(Window window)
    {
        _window = window;
    }

    public bool MoveRuleToPosition(uint ruleId, uint newPosition)
    {
        if (_proxyService == null)
            return false;

        return _proxyService.MoveRuleToPosition(ruleId, newPosition);
    }

    private void ResetRuleForm()
    {
        NewProcessName = "*";
        NewTargetHosts = "*";
        NewTargetPorts = "*";
        NewProtocol = "TCP";
        SelectedRuleAction = AvailableActions.FirstOrDefault();
        ProcessNameError = "";
    }

    public ProxyRulesViewModel(ObservableCollection<ProxyRule> proxyRules, ObservableCollection<ProxyConfig> availableProxyConfigs, Action<ProxyRule> onAddRule, Action onClose, ProxyBridgeService? proxyService = null, Action? onConfigChanged = null)
    {
        ProxyRules = proxyRules;
        _onAddRule = onAddRule;
        _onClose = onClose;
        _proxyService = proxyService;
        _onConfigChanged = onConfigChanged;

        // proxy configs first, then direct/block at end
        foreach (var pc in availableProxyConfigs)
            AvailableActions.Add(new RuleActionItem(pc.DisplayName, "PROXY", pc.Id));
        AvailableActions.Add(new RuleActionItem("Direct", "DIRECT", 0));
        AvailableActions.Add(new RuleActionItem("Block", "BLOCK", 0));
        _selectedRuleAction = AvailableActions.FirstOrDefault();

        foreach (var rule in ProxyRules)
        {
            rule.PropertyChanged += Rule_PropertyChanged;
        }

        AddRuleCommand = new RelayCommand(() =>
        {
            ResetRuleForm();
            IsAddRuleViewOpen = true;
        });

        SaveNewRuleCommand = new RelayCommand(() =>
        {
            NewProcessName = ValidationHelper.DefaultIfEmpty(NewProcessName);
            NewTargetHosts = ValidationHelper.DefaultIfEmpty(NewTargetHosts);
            NewTargetPorts = ValidationHelper.DefaultIfEmpty(NewTargetPorts);

            if (!_processNameRegex.IsMatch(NewProcessName))
            {
                ProcessNameError = "Invalid characters in process name. Only letters, numbers, spaces, dots, dashes, underscores, semicolons, quotes, parentheses, and * are allowed";
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
                var existRule = ProxyRules.FirstOrDefault(r => r.RuleId == _currentEditingRuleId);
                string action = SelectedRuleAction?.Action ?? "PROXY";
                uint pcId = SelectedRuleAction?.ProxyConfigId ?? 0;

                if (_proxyService.EditRule(_currentEditingRuleId, NewProcessName, NewTargetHosts, NewTargetPorts, NewProtocol, action, pcId))
                {
                    if (existRule != null)
                    {
                        existRule.ProcessName = NewProcessName;
                        existRule.TargetHosts = NewTargetHosts;
                        existRule.TargetPorts = NewTargetPorts;
                        existRule.Protocol = NewProtocol;
                        existRule.Action = action;
                        existRule.ProxyConfigId = pcId;
                        existRule.ProxyConfigDisplay = action == "PROXY" ? (SelectedRuleAction?.Label ?? "") : "";
                    }
                    _onConfigChanged?.Invoke();
                }

                _isEditMode = false;
                _currentEditingRuleId = 0;
            }
            else
            {
                string action = SelectedRuleAction?.Action ?? "PROXY";
                uint pcId = SelectedRuleAction?.ProxyConfigId ?? 0;
                var newRule = new ProxyRule
                {
                    ProcessName = NewProcessName,
                    TargetHosts = NewTargetHosts,
                    TargetPorts = NewTargetPorts,
                    Protocol = NewProtocol,
                    Action = action,
                    IsEnabled = true,
                    ProxyConfigId = pcId,
                    ProxyConfigDisplay = action == "PROXY" ? (SelectedRuleAction?.Label ?? "") : ""
                };

                newRule.PropertyChanged += Rule_PropertyChanged;
                _onAddRule?.Invoke(newRule);
            }

            IsAddRuleViewOpen = false;
            ResetRuleForm();
        });        CancelAddRuleCommand = new RelayCommand(() =>
        {
            ResetRuleForm();
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
                    _onConfigChanged?.Invoke();
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
            SelectedRuleAction = AvailableActions.FirstOrDefault(a =>
                a.Action == rule.Action && (a.Action != "PROXY" || a.ProxyConfigId == rule.ProxyConfigId))
                ?? AvailableActions.FirstOrDefault();
            ProcessNameError = "";
            IsAddRuleViewOpen = true;
        });

        ToggleSelectAllCommand = new RelayCommand(() =>
        {
            bool selectAll = !AllRulesSelected;
            foreach (var rule in ProxyRules)
            {
                rule.IsSelected = selectAll;
            }
            OnPropertyChanged(nameof(HasSelectedRules));
            OnPropertyChanged(nameof(AllRulesSelected));
        });

        DeleteSelectedRulesCommand = new RelayCommand(async () =>
        {
            var selectedRules = ProxyRules.Where(r => r.IsSelected).ToList();
            if (selectedRules.Count == 0)
                return;

            var confirmMsg = selectedRules.Count == 1
                ? $"Delete 1 selected rule?"
                : $"Delete {selectedRules.Count} selected rules?";

            var confirmed = await ShowConfirmDialogAsync("Delete Selected Rules", confirmMsg);
            if (!confirmed)
                return;

            foreach (var rule in selectedRules)
            {
                if (_proxyService != null && _proxyService.DeleteRule(rule.RuleId))
                {
                    ProxyRules.Remove(rule);
                }
            }

            _onConfigChanged?.Invoke();
            OnPropertyChanged(nameof(HasSelectedRules));
            OnPropertyChanged(nameof(AllRulesSelected));
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
            _onConfigChanged?.Invoke();
        }
        else if (e.PropertyName == nameof(ProxyRule.IsSelected))
        {
            OnPropertyChanged(nameof(HasSelectedRules));
            OnPropertyChanged(nameof(AllRulesSelected));
        }
    }

    private async System.Threading.Tasks.Task ShowMessageAsync(string title, string message)
    {
        if (_window == null)
            return;

        var messageBox = new Window
        {
            Title = title,
            Width = 450,
            Height = 180,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            Background = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#FF2D2D30"))
        };

        var stackPanel = new StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 15
        };

        stackPanel.Children.Add(new Avalonia.Controls.TextBlock
        {
            Text = message,
            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
            Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Colors.White),
            FontSize = 13
        });

        var buttonPanel = new StackPanel
        {
            Orientation = Avalonia.Layout.Orientation.Horizontal,
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
            Spacing = 10
        };

        var okButton = new Button
        {
            Content = "OK",
            Width = 80,
            Background = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#FF0E639C")),
            Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Colors.White)
        };
        okButton.Click += (s, e) => messageBox.Close();

        buttonPanel.Children.Add(okButton);
        stackPanel.Children.Add(buttonPanel);

        messageBox.Content = stackPanel;

        await messageBox.ShowDialog(_window);
    }
}

public class RuleActionItem
{
    public string Label { get; }
    public string Action { get; }   // "PROXY", "DIRECT", "BLOCK"
    public uint ProxyConfigId { get; }

    public RuleActionItem(string label, string action, uint proxyConfigId)
    {
        Label = label;
        Action = action;
        ProxyConfigId = proxyConfigId;
    }
}

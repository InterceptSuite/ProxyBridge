using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json.Serialization;
using System.Windows.Input;
using Avalonia.Controls;
using ProxyBridge.GUI.Services;
using ProxyBridge.GUI.Common;

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
    private Action? _onConfigChanged;
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
    public ICommand ToggleSelectAllCommand { get; }
    public ICommand ExportRulesCommand { get; }
    public ICommand ImportRulesCommand { get; }

    public bool HasSelectedRules => ProxyRules.Any(r => r.IsSelected);
    public bool AllRulesSelected => ProxyRules.Any() && ProxyRules.All(r => r.IsSelected);

    public void SetWindow(Window window)
    {
        _window = window;
    }

    private void ResetRuleForm()
    {
        NewProcessName = "*";
        NewTargetHosts = "*";
        NewTargetPorts = "*";
        NewProtocol = "TCP";
        NewProxyAction = "PROXY";
        ProcessNameError = "";
    }

    public ProxyRulesViewModel(ObservableCollection<ProxyRule> proxyRules, Action<ProxyRule> onAddRule, Action onClose, ProxyBridgeService? proxyService = null, Action? onConfigChanged = null)
    {
        ProxyRules = proxyRules;
        _onAddRule = onAddRule;
        _onClose = onClose;
        _proxyService = proxyService;
        _onConfigChanged = onConfigChanged;

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

            if (!System.Text.RegularExpressions.Regex.IsMatch(NewProcessName, @"^[a-zA-Z0-9\s._\-*;""\\:()]+$"))
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
                if (_proxyService.EditRule(_currentEditingRuleId, NewProcessName, NewTargetHosts, NewTargetPorts, NewProtocol, NewProxyAction))
                {
                    var existingRule = ProxyRules.FirstOrDefault(r => r.RuleId == _currentEditingRuleId);
                    if (existingRule != null)
                    {
                        existingRule.ProcessName = NewProcessName;
                        existingRule.TargetHosts = NewTargetHosts;
                        existingRule.TargetPorts = NewTargetPorts;
                        existingRule.Protocol = NewProtocol;
                        existingRule.Action = NewProxyAction;
                    }
                    _onConfigChanged?.Invoke();
                }

                _isEditMode = false;
                _currentEditingRuleId = 0;
            }
            else
            {
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
            NewProxyAction = rule.Action;
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

        ExportRulesCommand = new RelayCommand(async () =>
        {
            try
            {
                await ExportSelectedRulesAsync();
            }
            catch (Exception ex)
            {
                await ShowMessageAsync("Export Failed", $"Failed to export rules: {ex.Message}");
            }
        });

        ImportRulesCommand = new RelayCommand(async () =>
        {
            try
            {
                await ImportRulesAsync();
            }
            catch (Exception ex)
            {
                await ShowMessageAsync("Import Failed", $"Failed to import rules: {ex.Message}");
            }
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

    private async System.Threading.Tasks.Task ExportSelectedRulesAsync()
    {
        if (_window == null)
            return;

        var selectedRules = ProxyRules.Where(r => r.IsSelected).ToList();

        if (!selectedRules.Any())
        {
            await ShowMessageAsync("No Rules Selected", "Please select at least one rule to export.");
            return;
        }

        var saveDialog = new Avalonia.Platform.Storage.FilePickerSaveOptions
        {
            Title = "Export Proxy Rules",
            SuggestedFileName = "ProxyBridge-Rules.json",
            FileTypeChoices = new[]
            {
                new Avalonia.Platform.Storage.FilePickerFileType("JSON Files")
                {
                    Patterns = new[] { "*.json" }
                }
            }
        };

        var result = await _window.StorageProvider.SaveFilePickerAsync(saveDialog);

        if (result != null)
        {
            var exportData = selectedRules.Select(r => new ProxyRuleExport
            {
                ProcessNames = r.ProcessName,
                TargetHosts = r.TargetHosts,
                TargetPorts = r.TargetPorts,
                Protocol = r.Protocol,
                Action = r.Action,
                Enabled = r.IsEnabled
            }).ToList();

            var json = System.Text.Json.JsonSerializer.Serialize(exportData, ProxyRuleJsonContext.Default.ListProxyRuleExport);

            await System.IO.File.WriteAllTextAsync(result.Path.LocalPath, json);

            await ShowMessageAsync("Export Successful", $"Exported {selectedRules.Count} rule(s) to:\n{result.Path.LocalPath}");
        }
    }

    private async System.Threading.Tasks.Task ImportRulesAsync()
    {
        if (_window == null)
            return;

        if (_proxyService == null)
        {
            await ShowMessageAsync("Import Failed", "Proxy service is not available.");
            return;
        }

        var openDialog = new Avalonia.Platform.Storage.FilePickerOpenOptions
        {
            Title = "Import Proxy Rules",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new Avalonia.Platform.Storage.FilePickerFileType("JSON Files")
                {
                    Patterns = new[] { "*.json" }
                }
            }
        };

        var result = await _window.StorageProvider.OpenFilePickerAsync(openDialog);

        if (result != null && result.Count > 0)
        {
            var filePath = result[0].Path.LocalPath;

            var json = await System.IO.File.ReadAllTextAsync(filePath);

            var importedRules = System.Text.Json.JsonSerializer.Deserialize(json, ProxyRuleJsonContext.Default.ListProxyRuleExport);

            if (importedRules != null && importedRules.Count > 0)
            {
                int successCount = 0;
                foreach (var ruleData in importedRules)
                {
                    var ruleId = _proxyService.AddRule(
                        ruleData.ProcessNames,
                        ruleData.TargetHosts,
                        ruleData.TargetPorts,
                        ruleData.Protocol,
                        ruleData.Action
                    );

                    if (ruleId > 0)
                    {
                        var newRule = new ProxyRule
                        {
                            RuleId = ruleId,
                            ProcessName = ruleData.ProcessNames,
                            TargetHosts = ruleData.TargetHosts,
                            TargetPorts = ruleData.TargetPorts,
                            Protocol = ruleData.Protocol,
                            Action = ruleData.Action,
                            IsEnabled = ruleData.Enabled,
                            Index = ProxyRules.Count + 1
                        };

                        newRule.PropertyChanged += Rule_PropertyChanged;
                        ProxyRules.Add(newRule);

                        if (!ruleData.Enabled)
                        {
                            _proxyService.DisableRule(ruleId);
                        }

                        successCount++;
                    }
                }

                await ShowMessageAsync("Import Successful", $"Imported {successCount} rule(s) from:\n{filePath}");
            }
            else
            {
                await ShowMessageAsync("Import Failed", "No valid rules found in the selected file.");
            }
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

// JSON export/import model matching macOS format
public class ProxyRuleExport
{
    public string ProcessNames { get; set; } = "*";
    public string TargetHosts { get; set; } = "*";
    public string TargetPorts { get; set; } = "*";
    public string Protocol { get; set; } = "BOTH";
    public string Action { get; set; } = "DIRECT";
    public bool Enabled { get; set; } = true;
}

// JSON serialization context for NativeAOT compatibility
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(System.Collections.Generic.List<ProxyRuleExport>))]
[JsonSerializable(typeof(ProxyRuleExport))]
internal partial class ProxyRuleJsonContext : JsonSerializerContext
{
}

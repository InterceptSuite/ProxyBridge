using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using Avalonia.Controls;
using ProxyBridge.GUI.Common;
using ProxyBridge.GUI.Services;

namespace ProxyBridge.GUI.ViewModels;

public class LogFilterRuleViewModel : ViewModelBase
{
    public static readonly string[] Modes           = { "Include", "Exclude" };
    public static readonly string[] ProtocolOptions = { "All", "TCP", "UDP" };
    public static readonly string[] ActionOptions   = { "All", "Proxy", "Direct", "Blocked" };

    private string _mode        = "Include";
    private string _processName = "";
    private string _ip          = "";
    private string _port        = "";
    private string _protocol    = "All";
    private string _action      = "All";

    public string[] ModeList     => Modes;
    public string[] ProtocolList => ProtocolOptions;
    public string[] ActionList   => ActionOptions;

    public string Mode        { get => _mode;        set => SetProperty(ref _mode,        value); }
    public string ProcessName { get => _processName; set => SetProperty(ref _processName, value); }
    public string Ip          { get => _ip;          set => SetProperty(ref _ip,          value); }
    public string Port        { get => _port;        set => SetProperty(ref _port,        value); }
    public string Protocol    { get => _protocol;    set => SetProperty(ref _protocol,    value); }
    public string Action      { get => _action;      set => SetProperty(ref _action,      value); }
}

public class LogFiltersViewModel : ViewModelBase
{
    private readonly Action<List<LogFilterEntry>> _onSave;
    private readonly Action _onClose;

    public Loc Loc => Loc.Instance;

    public ObservableCollection<LogFilterRuleViewModel> Rules { get; } = new();

    public ICommand AddRuleCommand    { get; }
    public ICommand RemoveRuleCommand { get; }
    public ICommand ClearAllCommand   { get; }
    public ICommand SaveCommand       { get; }
    public ICommand CloseCommand      { get; }

    public LogFiltersViewModel(
        List<LogFilterEntry> existingFilters,
        Action<List<LogFilterEntry>> onSave,
        Action onClose)
    {
        _onSave = onSave;
        _onClose = onClose;

        foreach (var f in existingFilters)
        {
            Rules.Add(new LogFilterRuleViewModel
            {
                Mode        = f.Mode,
                ProcessName = f.ProcessName,
                Ip          = f.Ip,
                Port        = f.Port,
                Protocol    = f.Protocol,
                Action      = f.Action
            });
        }

        AddRuleCommand    = new RelayCommand(() => Rules.Add(new LogFilterRuleViewModel()));
        RemoveRuleCommand = new RelayCommandWithParameter<LogFilterRuleViewModel>(rule => Rules.Remove(rule));
        ClearAllCommand   = new RelayCommand(() => Rules.Clear());

        SaveCommand = new RelayCommand(() =>
        {
            var filters = Rules
                .Select(r => new LogFilterEntry
                {
                    Mode        = r.Mode,
                    ProcessName = r.ProcessName,
                    Ip          = r.Ip,
                    Port        = r.Port,
                    Protocol    = r.Protocol,
                    Action      = r.Action
                })
                .ToList();
            _onSave(filters);
            _onClose();
        });

        CloseCommand = new RelayCommand(() => _onClose());
    }
}

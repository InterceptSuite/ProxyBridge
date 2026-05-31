using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using Avalonia.Controls;
using ProxyBridge.GUI.Common;
using ProxyBridge.GUI.Services;

namespace ProxyBridge.GUI.ViewModels;

public class LogFilterRowViewModel : ViewModelBase
{
    private static readonly string[] _textOperators =
        { "Contains", "Not Contains", "Equals", "Not Equals", "Starts With" };
    private static readonly string[] _enumOperators =
        { "Equals", "Not Equals" };
    private static readonly string[] _actionValues =
        { "All", "Proxy", "Direct", "Blocked" };
    private static readonly string[] _protocolValues =
        { "All", "TCP", "UDP" };
    private static readonly string[] _noOptions = Array.Empty<string>();

    public static readonly string[] AvailableFields =
        { "Process Name", "IP", "Port", "Protocol", "Action" };

    private string _field = "Process Name";
    private string _operator = "Contains";
    private string _value = "";

    public string[] Fields => AvailableFields;

    // Dynamic — depends on selected field
    public string[] AvailableOperators =>
        IsValueDropdown ? _enumOperators : _textOperators;

    // Non-empty only for enum fields (Protocol, Action)
    public string[] ValueOptions => _field switch
    {
        "Action"   => _actionValues,
        "Protocol" => _protocolValues,
        _          => _noOptions
    };

    public bool IsValueDropdown => _field is "Action" or "Protocol";

    public string ValuePlaceholder => _field switch
    {
        "Process Name" => "e.g. chrome*, *.exe, *ch*",
        "IP"           => "e.g. 192.168.*, *.1, 10.*",
        "Port"         => "e.g. 443, 8080",
        _              => ""
    };

    public string Field
    {
        get => _field;
        set
        {
            if (!SetProperty(ref _field, value)) return;
            OnPropertyChanged(nameof(AvailableOperators));
            OnPropertyChanged(nameof(ValueOptions));
            OnPropertyChanged(nameof(IsValueDropdown));
            OnPropertyChanged(nameof(ValuePlaceholder));
            // reset operator and value to sensible defaults for the new field
            Operator = IsValueDropdown ? _enumOperators[0] : _textOperators[0];
            Value    = ValueOptions.Length > 0 ? ValueOptions[0] : "";
        }
    }

    public string Operator
    {
        get => _operator;
        set => SetProperty(ref _operator, value);
    }

    public string Value
    {
        get => _value;
        set => SetProperty(ref _value, value);
    }
}

public class LogFiltersViewModel : ViewModelBase
{
    private readonly Action<List<LogFilterEntry>> _onSave;
    private readonly Action _onClose;

    public Loc Loc => Loc.Instance;

    public ObservableCollection<LogFilterRowViewModel> FilterRows { get; } = new();

    public ICommand AddFilterCommand { get; }
    public ICommand RemoveFilterRowCommand { get; }
    public ICommand ClearAllCommand { get; }
    public ICommand SaveCommand { get; }
    public ICommand CloseCommand { get; }

    public LogFiltersViewModel(
        List<LogFilterEntry> existingFilters,
        Action<List<LogFilterEntry>> onSave,
        Action onClose)
    {
        _onSave = onSave;
        _onClose = onClose;

        foreach (var f in existingFilters)
        {
            FilterRows.Add(new LogFilterRowViewModel
            {
                Field = f.Field,
                Operator = f.Operator,
                Value = f.Value
            });
        }

        AddFilterCommand = new RelayCommand(() =>
            FilterRows.Add(new LogFilterRowViewModel()));

        RemoveFilterRowCommand =
            new RelayCommandWithParameter<LogFilterRowViewModel>(row => FilterRows.Remove(row));

        ClearAllCommand = new RelayCommand(() => FilterRows.Clear());

        SaveCommand = new RelayCommand(() =>
        {
            var filters = FilterRows
                .Select(r => new LogFilterEntry
                {
                    Field    = r.Field,
                    Operator = r.Operator,
                    Value    = r.Value
                })
                .ToList();
            _onSave(filters);
            _onClose();
        });

        CloseCommand = new RelayCommand(() => _onClose());
    }
}

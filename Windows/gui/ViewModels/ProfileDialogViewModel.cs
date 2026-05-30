using System;
using System.Windows.Input;
using ProxyBridge.GUI.Common;

namespace ProxyBridge.GUI.ViewModels;

public class ProfileDialogViewModel : ViewModelBase
{
    private string _inputValue;
    private readonly Action<string> _onConfirm;

    public string Message { get; }
    public bool IsInputMode { get; }

    public string InputValue
    {
        get => _inputValue;
        set => SetProperty(ref _inputValue, value);
    }

    public ICommand ConfirmCommand { get; }
    public ICommand CancelCommand { get; }

    public ProfileDialogViewModel(string message, bool isInputMode, string defaultValue,
        Action<string> onConfirm, Action onCancel)
    {
        Message = message;
        IsInputMode = isInputMode;
        _inputValue = defaultValue;
        _onConfirm = onConfirm;

        ConfirmCommand = new RelayCommand(() => _onConfirm(_inputValue));
        CancelCommand = new RelayCommand(onCancel);
    }
}

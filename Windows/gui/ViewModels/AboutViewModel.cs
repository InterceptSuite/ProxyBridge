using System;
using System.Reflection;
using System.Windows.Input;

namespace ProxyBridge.GUI.ViewModels;

public class AboutViewModel
{
    public string Version { get; }
    public ICommand CloseCommand { get; }

    public AboutViewModel() : this(() => { })
    {
    }

    public AboutViewModel(Action onClose)
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        Version = version != null
            ? $"Version {version.Major}.{version.Minor}.{version.Build}"
            : "Version 1.0.0";

        CloseCommand = new RelayCommand(onClose);
    }
}

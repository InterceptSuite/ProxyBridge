using Avalonia.Controls;
using Avalonia.Input;

namespace ProxyBridge.GUI.Views;

public partial class LogFiltersWindow : Window
{
    public LogFiltersWindow()
    {
        InitializeComponent();
        KeyDown += (_, e) => { if (e.Key == Key.Escape) Close(); };
    }
}

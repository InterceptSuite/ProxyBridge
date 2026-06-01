using Avalonia.Controls;
using Avalonia.Input;

namespace ProxyBridge.GUI.Views;

public partial class UpdateNotificationWindow : Window
{
    public UpdateNotificationWindow()
    {
        InitializeComponent();
        KeyDown += (_, e) => { if (e.Key == Key.Escape) Close(); };
    }
}
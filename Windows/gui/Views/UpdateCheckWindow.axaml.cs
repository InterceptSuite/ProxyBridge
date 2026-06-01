using Avalonia.Controls;
using Avalonia.Input;

namespace ProxyBridge.GUI.Views;

public partial class UpdateCheckWindow : Window
{
    public UpdateCheckWindow()
    {
        InitializeComponent();
        KeyDown += (_, e) => { if (e.Key == Key.Escape) Close(); };
    }
}
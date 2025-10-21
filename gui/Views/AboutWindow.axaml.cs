using Avalonia.Controls;
using System.Diagnostics;
using Avalonia.Input;

namespace ProxyBridge.GUI.Views;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
    }

    private void OnWebsiteClick(object? sender, PointerPressedEventArgs e)
    {
        OpenUrl("https://interceptsuite.com");
    }

    private void OnGitHubClick(object? sender, PointerPressedEventArgs e)
    {
        OpenUrl("https://github.com/InterceptSuite/ProxyBridge");
    }

    private void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch
        {
            // Silently fail if browser can't be opened
        }
    }
}

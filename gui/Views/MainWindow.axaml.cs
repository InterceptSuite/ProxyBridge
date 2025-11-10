using Avalonia.Controls;
using ProxyBridge.GUI.ViewModels;
using System;
using System.ComponentModel;
using Avalonia.Interactivity;

namespace ProxyBridge.GUI.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // Set window reference in ViewModel
        this.Opened += (s, e) =>
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.SetMainWindow(this);
            }
        };

        // ,inimize to tray
        this.Closing += (s, e) =>
        {
            e.Cancel = true;
            this.Hide();
        };
    }

    private void OnChangeLanguageEnglish(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel vm)
        {
            vm.ChangeLanguage("en");
        }
    }

    private void OnChangeLanguageChinese(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel vm)
        {
            vm.ChangeLanguage("zh");
        }
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        if (e.CloseReason == WindowCloseReason.ApplicationShutdown)
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.Cleanup();
            }
            base.OnClosing(e);
            return;
        }
        e.Cancel = true;
        this.Hide();
    }
}

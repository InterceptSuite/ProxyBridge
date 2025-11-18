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

        // verify if user cclose app or minimize to tray
        if (DataContext is MainWindowViewModel viewModel)
        {
            if (viewModel.CloseToTray)
            {
                // minimize to tray
                e.Cancel = true;
                this.Hide();
            }
            else
            {
                // exit the app if not tray
                viewModel.Cleanup();
                base.OnClosing(e);
            }
        }
        else
        {
            // fallback to tray
            e.Cancel = true;
            this.Hide();
        }
    }
}

using Avalonia.Controls;
using ProxyBridge.GUI.ViewModels;
using System;
using System.ComponentModel;

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

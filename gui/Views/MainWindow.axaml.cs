using Avalonia.Controls;
using ProxyBridge.GUI.ViewModels;
using System;

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

        // Cleanup on close
        this.Closing += (s, e) =>
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.Cleanup();
            }
        };
    }
}

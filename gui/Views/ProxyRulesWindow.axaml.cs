using Avalonia.Controls;
using Avalonia.Interactivity;
using ProxyBridge.GUI.ViewModels;

namespace ProxyBridge.GUI.Views;

public partial class ProxyRulesWindow : Window
{
    public ProxyRulesWindow()
    {
        InitializeComponent();
    }

    private void ActionComboBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox comboBox &&
            comboBox.SelectedItem is ComboBoxItem item &&
            item.Tag is string tag &&
            DataContext is ProxyRulesViewModel vm)
        {
            vm.NewProxyAction = tag;
        }
    }
}
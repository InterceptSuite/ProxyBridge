using Avalonia.Controls;
using ProxyBridge.GUI.ViewModels;

namespace ProxyBridge.GUI.Views;

public partial class ProxySettingsWindow : Window
{
    public ProxySettingsWindow()
    {
        InitializeComponent();

        // Handle save with proper ProxyType value
        this.Opened += (s, e) =>
        {
            if (DataContext is ProxySettingsViewModel vm)
            {
                var originalSave = vm.SaveCommand;

                // Override to get the actual selected type
                this.FindControl<ComboBox>("ProxyTypeComboBox")!.SelectionChanged += (_, __) =>
                {
                    var combo = this.FindControl<ComboBox>("ProxyTypeComboBox");
                    if (combo?.SelectedItem is ComboBoxItem item && item.Tag is string tag)
                    {
                        vm.ProxyType = tag;
                    }
                };

                // Set initial value
                var comboBox = this.FindControl<ComboBox>("ProxyTypeComboBox");
                if (comboBox?.SelectedItem is ComboBoxItem initialItem && initialItem.Tag is string initialTag)
                {
                    vm.ProxyType = initialTag;
                }
            }
        };
    }
}

using System.ComponentModel;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using ProxyBridge.GUI.ViewModels;

namespace ProxyBridge.GUI.Views;

public partial class ProxySettingsWindow : Window
{
    private bool _isUpdatingFromViewModel = false;
    private ProxySettingsViewModel? _boundViewModel;

    public ProxySettingsWindow()
    {
        InitializeComponent();

        KeyDown += (_, e) => { if (e.Key == Key.Escape) Close(); };

        this.DataContextChanged += OnDataContextChanged;
        this.Closed += (_, _) =>
        {
            if (_boundViewModel != null)
                _boundViewModel.PropertyChanged -= ViewModel_PropertyChanged;
        };

        this.Opened += (s, e) =>
        {
            if (DataContext is ProxySettingsViewModel vm)
                UpdateEditTypeComboBox(vm.NewType);
        };
    }

    private void OnDataContextChanged(object? sender, System.EventArgs e)
    {
        if (_boundViewModel != null)
            _boundViewModel.PropertyChanged -= ViewModel_PropertyChanged;

        _boundViewModel = DataContext as ProxySettingsViewModel;

        if (_boundViewModel != null)
        {
            _boundViewModel.PropertyChanged += ViewModel_PropertyChanged;

            var editComboBox = this.FindControl<ComboBox>("EditTypeComboBox");
            if (editComboBox != null)
            {
                editComboBox.SelectionChanged -= EditTypeComboBox_SelectionChanged;
                editComboBox.SelectionChanged += EditTypeComboBox_SelectionChanged;
            }
        }
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is ProxySettingsViewModel vm && e.PropertyName == nameof(ProxySettingsViewModel.NewType))
        {
            UpdateEditTypeComboBox(vm.NewType);
        }
    }

    private void UpdateEditTypeComboBox(string typeTag)
    {
        var comboBox = this.FindControl<ComboBox>("EditTypeComboBox");
        if (comboBox == null) return;

        _isUpdatingFromViewModel = true;
        comboBox.SelectedItem = comboBox.Items
            .OfType<ComboBoxItem>()
            .FirstOrDefault(item => item.Tag is string tag &&
                tag.Equals(typeTag, System.StringComparison.OrdinalIgnoreCase));
        _isUpdatingFromViewModel = false;
    }

    private void EditTypeComboBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_isUpdatingFromViewModel) return;

        if (sender is ComboBox comboBox &&
            comboBox.SelectedItem is ComboBoxItem item &&
            item.Tag is string tag &&
            DataContext is ProxySettingsViewModel vm)
        {
            vm.NewType = tag;
        }
    }
}

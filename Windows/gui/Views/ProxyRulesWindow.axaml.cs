using System;
using System.ComponentModel;
using System.Globalization;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Interactivity;
using ProxyBridge.GUI.ViewModels;

namespace ProxyBridge.GUI.Views;

public class SelectAllTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool allSelected && allSelected ? "Deselect All" : "Select All";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class SelectAllIconConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is bool allSelected && allSelected ? "☑" : "☐";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public partial class ProxyRulesWindow : Window
{
    private bool _isUpdatingFromViewModel = false;

    public ProxyRulesWindow()
    {
        InitializeComponent();

        if (this.FindControl<ComboBox>("ProtocolComboBox") is ComboBox protocolComboBox)
        {
            protocolComboBox.SelectionChanged += ProtocolComboBox_SelectionChanged;
        }

        this.DataContextChanged += ProxyRulesWindow_DataContextChanged;
    }

    private void ProxyRulesWindow_DataContextChanged(object? sender, EventArgs e)
    {
        if (DataContext is ProxyRulesViewModel vm)
        {
            vm.PropertyChanged += ViewModel_PropertyChanged;

            UpdateComboBoxSelections(vm);
        }
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is ProxyRulesViewModel vm)
        {
            if (e.PropertyName == nameof(ProxyRulesViewModel.NewProtocol))
            {
                UpdateProtocolComboBox(vm.NewProtocol);
            }
            else if (e.PropertyName == nameof(ProxyRulesViewModel.NewProxyAction))
            {
                UpdateActionComboBox(vm.NewProxyAction);
            }
        }
    }

    private void UpdateComboBoxSelections(ProxyRulesViewModel vm)
    {
        UpdateProtocolComboBox(vm.NewProtocol);
        UpdateActionComboBox(vm.NewProxyAction);
    }

    private void UpdateProtocolComboBox(string protocol)
    {
        if (this.FindControl<ComboBox>("ProtocolComboBox") is ComboBox protocolComboBox)
        {
            _isUpdatingFromViewModel = true;

            foreach (var item in protocolComboBox.Items)
            {
                if (item is ComboBoxItem comboBoxItem &&
                    comboBoxItem.Tag is string tag &&
                    tag.Equals(protocol, StringComparison.OrdinalIgnoreCase))
                {
                    protocolComboBox.SelectedItem = comboBoxItem;
                    break;
                }
            }

            _isUpdatingFromViewModel = false;
        }
    }

    private void UpdateActionComboBox(string action)
    {
        if (this.FindControl<ComboBox>("ActionComboBox") is ComboBox actionComboBox)
        {
            _isUpdatingFromViewModel = true;

            foreach (var item in actionComboBox.Items)
            {
                if (item is ComboBoxItem comboBoxItem &&
                    comboBoxItem.Tag is string tag &&
                    tag.Equals(action, StringComparison.OrdinalIgnoreCase))
                {
                    actionComboBox.SelectedItem = comboBoxItem;
                    break;
                }
            }

            _isUpdatingFromViewModel = false;
        }
    }

    private void ActionComboBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        // dont update ViewModel when updating from Viewmodel
        if (_isUpdatingFromViewModel)
            return;

        if (sender is ComboBox comboBox &&
            comboBox.SelectedItem is ComboBoxItem item &&
            item.Tag is string tag &&
            DataContext is ProxyRulesViewModel vm)
        {
            vm.NewProxyAction = tag;
        }
    }

    private void ProtocolComboBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_isUpdatingFromViewModel)
            return;

        if (sender is ComboBox comboBox &&
            comboBox.SelectedItem is ComboBoxItem item &&
            item.Tag is string tag &&
            DataContext is ProxyRulesViewModel vm)
        {
            vm.NewProtocol = tag;
        }
    }
}
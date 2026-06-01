using System;
using System.ComponentModel;
using System.Globalization;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Interactivity;
using Avalonia.Input;
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

        KeyDown += (_, e) => { if (e.Key == Key.Escape) Close(); };

        if (this.FindControl<ComboBox>("ProtocolComboBox") is ComboBox protocolComboBox)
        {
            protocolComboBox.SelectionChanged += ProtocolComboBox_SelectionChanged;
        }

        this.DataContextChanged += ProxyRulesWindow_DataContextChanged;

        if (this.FindControl<ItemsControl>("RulesItemsControl") is ItemsControl itemsControl)
        {
            itemsControl.AddHandler(DragDrop.DropEvent, Rules_Drop);
            itemsControl.AddHandler(DragDrop.DragOverEvent, Rules_DragOver);
        }
    }

    private ProxyRulesViewModel? _boundViewModel;

    private void ProxyRulesWindow_DataContextChanged(object? sender, EventArgs e)
    {
        if (_boundViewModel != null)
            _boundViewModel.PropertyChanged -= ViewModel_PropertyChanged;

        _boundViewModel = DataContext as ProxyRulesViewModel;

        if (_boundViewModel != null)
        {
            _boundViewModel.PropertyChanged += ViewModel_PropertyChanged;
            UpdateComboBoxSelections(_boundViewModel);
        }
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is ProxyRulesViewModel vm && e.PropertyName == nameof(ProxyRulesViewModel.NewProtocol))
        {
            UpdateProtocolComboBox(vm.NewProtocol);
        }
    }

    private void UpdateComboBoxSelections(ProxyRulesViewModel vm)
    {
        UpdateProtocolComboBox(vm.NewProtocol);
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

    private async void Rule_PointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (sender is not Border border || border.DataContext is not ProxyRule rule)
            return;

        var dragData = new DataObject();
        dragData.Set("DraggedRule", rule);

        var result = await DragDrop.DoDragDrop(e, dragData, DragDropEffects.Move);

        if (result == DragDropEffects.Move && DataContext is ProxyRulesViewModel vm)
        {
            // refsh indices after drag completes
            for (int i = 0; i < vm.ProxyRules.Count; i++)
            {
                vm.ProxyRules[i].Index = i + 1;
            }
        }
    }

    private void Rules_DragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = DragDropEffects.Move;
    }

    private void Rules_Drop(object? sender, DragEventArgs e)
    {
        if (DataContext is not ProxyRulesViewModel vm)
            return;

        if (e.Data.Get("DraggedRule") is not ProxyRule draggedRule)
            return;

        if (e.Source is Control control)
        {
            var current = control;
            while (current != null && current is not Border)
            {
                current = current.Parent as Control;
            }

            if (current is Border border && border.DataContext is ProxyRule targetRule)
            {
                if (draggedRule.RuleId == targetRule.RuleId)
                    return;

                int draggedIndex = vm.ProxyRules.IndexOf(draggedRule);
                int targetIndex = vm.ProxyRules.IndexOf(targetRule);

                if (draggedIndex == -1 || targetIndex == -1 || draggedIndex == targetIndex)
                    return;

                uint newPosition = (uint)(targetIndex + 1);
                if (vm.MoveRuleToPosition(draggedRule.RuleId, newPosition))
                {
                    vm.ProxyRules.Move(draggedIndex, targetIndex);

                    for (int i = 0; i < vm.ProxyRules.Count; i++)
                    {
                        vm.ProxyRules[i].Index = i + 1;
                    }
                }
            }
        }
    }
}
using System;
using Avalonia.Controls;

namespace ProxyBridge.GUI.Views;

public partial class ProfileDialogWindow : Window
{
    public bool Confirmed { get; private set; }
    public string InputValue { get; private set; } = "";

    public ProfileDialogWindow()
    {
        InitializeComponent();
    }

    public ProfileDialogWindow(string title, string message, bool isInputMode, string defaultValue = "")
    {
        InitializeComponent();
        Title = title;
        DataContext = new ViewModels.ProfileDialogViewModel(
            message, isInputMode, defaultValue,
            value => { Confirmed = true; InputValue = value?.Trim() ?? ""; Close(); },
            () => { Confirmed = false; Close(); }
        );
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        if (this.FindControl<TextBox>("InputBox") is { } box)
        {
            box.Focus();
            box.SelectAll();
        }
    }
}

using System.Windows.Input;

namespace ProxyBridge.GUI.ViewModels;

public class ProfileSwitchItem
{
    public string Name { get; init; } = "";
    public bool IsActive { get; init; }
    public ICommand Command { get; init; } = default!;
}

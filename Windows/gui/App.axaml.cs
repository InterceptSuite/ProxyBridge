using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Controls;
using ProxyBridge.GUI.ViewModels;
using ProxyBridge.GUI.Views;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace ProxyBridge.GUI;

public class App : Application
{
    public static bool StartMinimized { get; set; }
    private EventWaitHandle? _showWindowEvent;
    private CancellationTokenSource? _eventListenerCts;
    private const string EventName = "Global\\ProxyBridge_ShowWindow_Event_v4.0";

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow { DataContext = new MainWindowViewModel() };

            if (StartMinimized)
            {
                desktop.MainWindow.WindowState = WindowState.Minimized;
                desktop.MainWindow.ShowInTaskbar = false;
            }

            try
            {
                _showWindowEvent = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
                _eventListenerCts = new CancellationTokenSource();
                Task.Run(() => ListenForActivationSignal(_eventListenerCts.Token));
            }
            catch { }

            desktop.ShutdownRequested += (s, e) =>
            {
                _eventListenerCts?.Cancel();
                _showWindowEvent?.Dispose();
                (desktop.MainWindow?.DataContext as MainWindowViewModel)?.Cleanup();
            };

            desktop.ShutdownMode = Avalonia.Controls.ShutdownMode.OnMainWindowClose;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private async Task ListenForActivationSignal(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var signaled = await Task.Run(() => _showWindowEvent?.WaitOne(1000) ?? false, token);
                if (signaled && !token.IsCancellationRequested)
                {
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                        TrayIcon_Show(null, EventArgs.Empty));
                }
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    public void TrayIcon_Show(object? sender, EventArgs e)
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainWindow = desktop.MainWindow;
            if (mainWindow != null)
            {
                mainWindow.ShowInTaskbar = true;
                mainWindow.Show();
                mainWindow.WindowState = WindowState.Normal;
                mainWindow.Activate();
            }
        }
    }

    public void TrayIcon_Exit(object? sender, EventArgs e)
    {
        (ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown();
    }
}

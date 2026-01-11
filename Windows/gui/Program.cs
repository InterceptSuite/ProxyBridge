using Avalonia;
using System;
using System.Threading;

namespace ProxyBridge.GUI;

class Program
{
    private static Mutex? _instanceMutex;
    private const string MutexName = "Global\\ProxyBridge_SingleInstance_Mutex_v3.0";
    private const string EventName = "Global\\ProxyBridge_ShowWindow_Event_v3.0";

    [STAThread]
    public static void Main(string[] args)
    {
        _instanceMutex = new Mutex(true, MutexName, out bool isNewInstance);

        if (!isNewInstance)
        {
            SignalExistingInstance();
            return;
        }

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        finally
        {
            _instanceMutex?.ReleaseMutex();
            _instanceMutex?.Dispose();
        }
    }

    private static void SignalExistingInstance()
    {
        try
        {
            using var showEvent = EventWaitHandle.OpenExisting(EventName);
            showEvent.Set();
        }
        catch { }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}

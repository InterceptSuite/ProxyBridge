using System;
using ProxyBridge.GUI.Interop;

namespace ProxyBridge.GUI.Services;

public class ProxyBridgeService : IDisposable
{
    private ProxyBridgeNative.LogCallback? _logCallback;
    private ProxyBridgeNative.ConnectionCallback? _connectionCallback;
    private bool _isRunning;

    public event Action<string>? LogReceived;
    public event Action<string, uint, string, ushort, string>? ConnectionReceived;

    public ProxyBridgeService()
    {
        _logCallback = OnLogReceived;
        _connectionCallback = OnConnectionReceived;

        ProxyBridgeNative.ProxyBridge_SetLogCallback(_logCallback);
        ProxyBridgeNative.ProxyBridge_SetConnectionCallback(_connectionCallback);
    }

    private void OnLogReceived(string message)
    {
        LogReceived?.Invoke(message);
    }

    private void OnConnectionReceived(string processName, uint pid, string destIp, ushort destPort, string proxyInfo)
    {
        ConnectionReceived?.Invoke(processName, pid, destIp, destPort, proxyInfo);
    }

    public bool Start()
    {
        if (_isRunning)
            return true;

        _isRunning = ProxyBridgeNative.ProxyBridge_Start();
        return _isRunning;
    }

    public bool Stop()
    {
        if (!_isRunning)
            return true;

        _isRunning = !ProxyBridgeNative.ProxyBridge_Stop();
        return !_isRunning;
    }

    public bool SetProxyConfig(string type, string ip, ushort port, string username, string password)
    {
        var proxyType = type.ToUpper() == "HTTP"
            ? ProxyBridgeNative.ProxyType.HTTP
            : ProxyBridgeNative.ProxyType.SOCKS5;

        return ProxyBridgeNative.ProxyBridge_SetProxyConfig(proxyType, ip, port, username, password);
    }

    public uint AddRule(string processName, string targetHosts, string targetPorts, string protocol, string action)
    {
        var ruleAction = action.ToUpper() switch
        {
            "DIRECT" => ProxyBridgeNative.RuleAction.DIRECT,
            "BLOCK" => ProxyBridgeNative.RuleAction.BLOCK,
            _ => ProxyBridgeNative.RuleAction.PROXY
        };

        var ruleProtocol = protocol.ToUpper() switch
        {
            "UDP" => ProxyBridgeNative.RuleProtocol.UDP,
            "BOTH" => ProxyBridgeNative.RuleProtocol.BOTH,
            "TCP+UDP" => ProxyBridgeNative.RuleProtocol.BOTH,
            _ => ProxyBridgeNative.RuleProtocol.TCP
        };

        return ProxyBridgeNative.ProxyBridge_AddRule(processName, targetHosts, targetPorts, ruleProtocol, ruleAction);
    }

    public bool EnableRule(uint ruleId)
    {
        return ProxyBridgeNative.ProxyBridge_EnableRule(ruleId);
    }

    public bool DisableRule(uint ruleId)
    {
        return ProxyBridgeNative.ProxyBridge_DisableRule(ruleId);
    }

    public bool DeleteRule(uint ruleId)
    {
        return ProxyBridgeNative.ProxyBridge_DeleteRule(ruleId);
    }

    public bool EditRule(uint ruleId, string processName, string targetHosts, string targetPorts, string protocol, string action)
    {
        var ruleAction = action.ToUpper() switch
        {
            "DIRECT" => ProxyBridgeNative.RuleAction.DIRECT,
            "BLOCK" => ProxyBridgeNative.RuleAction.BLOCK,
            _ => ProxyBridgeNative.RuleAction.PROXY
        };

        var ruleProtocol = protocol.ToUpper() switch
        {
            "UDP" => ProxyBridgeNative.RuleProtocol.UDP,
            "BOTH" => ProxyBridgeNative.RuleProtocol.BOTH,
            "TCP+UDP" => ProxyBridgeNative.RuleProtocol.BOTH,
            _ => ProxyBridgeNative.RuleProtocol.TCP
        };

        return ProxyBridgeNative.ProxyBridge_EditRule(ruleId, processName, targetHosts, targetPorts, ruleProtocol, ruleAction);
    }

    public void SetDnsViaProxy(bool enable)
    {
        ProxyBridgeNative.ProxyBridge_SetDnsViaProxy(enable);
    }

    public string TestConnection(string targetHost, ushort targetPort)
    {
        var buffer = new System.Text.StringBuilder(4096);
        int result = ProxyBridgeNative.ProxyBridge_TestConnection(
            targetHost,
            targetPort,
            buffer,
            (UIntPtr)buffer.Capacity);

        return buffer.ToString();
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}

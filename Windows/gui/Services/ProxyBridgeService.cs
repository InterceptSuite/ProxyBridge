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

    public uint AddProxyConfig(string type, string ip, ushort port, string username, string password)
    {
        var proxyType = string.Equals(type, "HTTP", StringComparison.OrdinalIgnoreCase)
            ? ProxyBridgeNative.ProxyType.HTTP
            : ProxyBridgeNative.ProxyType.SOCKS5;

        return AddProxyConfigCore(proxyType, ip, port, username, password);
    }

    private static uint AddProxyConfigCore(ProxyBridgeNative.ProxyType proxyType, string ip, ushort port, string username, string password)
    {
        return ProxyBridgeNative.ProxyBridge_AddProxyConfig(proxyType, ip, port, username, password);
    }

    public bool EditProxyConfig(uint configId, string type, string ip, ushort port, string username, string password)
    {
        var proxyType = string.Equals(type, "HTTP", StringComparison.OrdinalIgnoreCase)
            ? ProxyBridgeNative.ProxyType.HTTP
            : ProxyBridgeNative.ProxyType.SOCKS5;

        return ProxyBridgeNative.ProxyBridge_EditProxyConfig(configId, proxyType, ip, port, username, password);
    }

    public bool DeleteProxyConfig(uint configId)
    {
        return ProxyBridgeNative.ProxyBridge_DeleteProxyConfig(configId);
    }

    public string TestProxyConfig(uint configId, string targetHost, ushort targetPort)
    {
        var buffer = new System.Text.StringBuilder(4096);
        ProxyBridgeNative.ProxyBridge_TestProxyConfig(configId, targetHost, targetPort, buffer, (UIntPtr)buffer.Capacity);
        return buffer.ToString();
    }

    public uint AddRule(string processName, string targetHosts, string targetPorts, string protocol, string action, uint proxyConfigId = 0)
    {
        ProxyBridgeNative.RuleAction ruleAction;
        if (string.Equals(action, "DIRECT", StringComparison.OrdinalIgnoreCase))
            ruleAction = ProxyBridgeNative.RuleAction.DIRECT;
        else if (string.Equals(action, "BLOCK", StringComparison.OrdinalIgnoreCase))
            ruleAction = ProxyBridgeNative.RuleAction.BLOCK;
        else
            ruleAction = ProxyBridgeNative.RuleAction.PROXY;

        ProxyBridgeNative.RuleProtocol ruleProtocol;
        if (string.Equals(protocol, "UDP", StringComparison.OrdinalIgnoreCase))
            ruleProtocol = ProxyBridgeNative.RuleProtocol.UDP;
        else if (string.Equals(protocol, "BOTH", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(protocol, "TCP+UDP", StringComparison.OrdinalIgnoreCase))
            ruleProtocol = ProxyBridgeNative.RuleProtocol.BOTH;
        else
            ruleProtocol = ProxyBridgeNative.RuleProtocol.TCP;

        return ProxyBridgeNative.ProxyBridge_AddRule(processName, targetHosts, targetPorts, ruleProtocol, ruleAction, proxyConfigId);
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

    public bool EditRule(uint ruleId, string processName, string targetHosts, string targetPorts, string protocol, string action, uint proxyConfigId = 0)
    {
        ProxyBridgeNative.RuleAction ruleAction;
        if (string.Equals(action, "DIRECT", StringComparison.OrdinalIgnoreCase))
            ruleAction = ProxyBridgeNative.RuleAction.DIRECT;
        else if (string.Equals(action, "BLOCK", StringComparison.OrdinalIgnoreCase))
            ruleAction = ProxyBridgeNative.RuleAction.BLOCK;
        else
            ruleAction = ProxyBridgeNative.RuleAction.PROXY;

        ProxyBridgeNative.RuleProtocol ruleProtocol;
        if (string.Equals(protocol, "UDP", StringComparison.OrdinalIgnoreCase))
            ruleProtocol = ProxyBridgeNative.RuleProtocol.UDP;
        else if (string.Equals(protocol, "BOTH", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(protocol, "TCP+UDP", StringComparison.OrdinalIgnoreCase))
            ruleProtocol = ProxyBridgeNative.RuleProtocol.BOTH;
        else
            ruleProtocol = ProxyBridgeNative.RuleProtocol.TCP;

        return ProxyBridgeNative.ProxyBridge_EditRule(ruleId, processName, targetHosts, targetPorts, ruleProtocol, ruleAction, proxyConfigId);
    }

    public uint GetRulePosition(uint ruleId)
    {
        return ProxyBridgeNative.ProxyBridge_GetRulePosition(ruleId);
    }

    public bool MoveRuleToPosition(uint ruleId, uint newPosition)
    {
        return ProxyBridgeNative.ProxyBridge_MoveRuleToPosition(ruleId, newPosition);
    }

    public void SetDnsViaProxy(bool enable)
    {
        ProxyBridgeNative.ProxyBridge_SetDnsViaProxy(enable);
    }

    public void SetLocalhostViaProxy(bool enable)
    {
        ProxyBridgeNative.ProxyBridge_SetLocalhostViaProxy(enable);
    }

    public static void SetTrafficLoggingEnabled(bool enable)
    {
        ProxyBridgeNative.ProxyBridge_SetTrafficLoggingEnabled(enable);
    }

    public void Dispose()
    {
        if (_isRunning)
        {
            Stop(); // removing the threads, C code handle close no need to manually handle drives
        }
        GC.SuppressFinalize(this);
    }
}

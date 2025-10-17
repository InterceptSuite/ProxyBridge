using System;
using System.Net;
using System.Text.RegularExpressions;
using System.Windows.Input;

namespace ProxyBridge.GUI.ViewModels;

public class ProxySettingsViewModel : ViewModelBase
{
    private string _proxyIp = "";
    private string _proxyPort = "";
    private string _proxyType = "SOCKS5";
    private string _ipError = "";
    private string _portError = "";
    private Action<string, string, string>? _onSave;
    private Action? _onClose;

    public string ProxyIp
    {
        get => _proxyIp;
        set
        {
            SetProperty(ref _proxyIp, value);
            IpError = "";
        }
    }

    public string ProxyPort
    {
        get => _proxyPort;
        set
        {
            SetProperty(ref _proxyPort, value);
            PortError = "";
        }
    }

    public string ProxyType
    {
        get => _proxyType;
        set => SetProperty(ref _proxyType, value);
    }

    public string IpError
    {
        get => _ipError;
        set => SetProperty(ref _ipError, value);
    }

    public string PortError
    {
        get => _portError;
        set => SetProperty(ref _portError, value);
    }

    public ICommand SaveCommand { get; }
    public ICommand CancelCommand { get; }

    private bool IsValidIpOrDomain(string input)
    {
        if (IPAddress.TryParse(input, out _))
        {
            return true;
        }

        var domainRegex = new Regex(@"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$");
        return domainRegex.IsMatch(input);
    }

    public ProxySettingsViewModel(Action<string, string, string> onSave, Action onClose)
    {
        _onSave = onSave;
        _onClose = onClose;

        SaveCommand = new RelayCommand(() =>
        {
            bool isValid = true;

            if (string.IsNullOrWhiteSpace(ProxyIp))
            {
                IpError = "IP address or domain is required";
                isValid = false;
            }
            else if (!IsValidIpOrDomain(ProxyIp))
            {
                IpError = "Invalid IP address or domain name";
                isValid = false;
            }

            if (string.IsNullOrWhiteSpace(ProxyPort))
            {
                PortError = "Port is required";
                isValid = false;
            }
            else if (!int.TryParse(ProxyPort, out int port) || port < 1 || port > 65535)
            {
                PortError = "Port must be between 1 and 65535";
                isValid = false;
            }

            if (isValid)
            {
                _onSave?.Invoke(ProxyType, ProxyIp, ProxyPort);
            }
        });

        CancelCommand = new RelayCommand(() =>
        {
            _onClose?.Invoke();
        });
    }
}

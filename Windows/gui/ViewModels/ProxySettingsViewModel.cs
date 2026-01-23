using System;
using System.Net;
using System.Text.RegularExpressions;
using System.Windows.Input;
using ProxyBridge.GUI.Services;
using ProxyBridge.GUI.Common;

namespace ProxyBridge.GUI.ViewModels;

public class ProxySettingsViewModel : ViewModelBase
{
    private readonly Loc _loc = Loc.Instance;
    public Loc Loc => _loc;

    private string _proxyIp = "";
    private string _proxyPort = "";
    private string _proxyType = "SOCKS5";
    private string _proxyUsername = "";
    private string _proxyPassword = "";
    private string _ipError = "";
    private string _portError = "";
    private bool _isTestViewOpen = false;
    private string _testTargetHost = "google.com";
    private string _testTargetPort = "80";
    private string _testOutput = "";
    private bool _isTesting = false;
    private Action<string, string, string, string, string>? _onSave;
    private Action? _onClose;
    private Services.ProxyBridgeService? _proxyService;

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

    public string ProxyUsername
    {
        get => _proxyUsername;
        set => SetProperty(ref _proxyUsername, value);
    }

    public string ProxyPassword
    {
        get => _proxyPassword;
        set => SetProperty(ref _proxyPassword, value);
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

    public bool IsTestViewOpen
    {
        get => _isTestViewOpen;
        set => SetProperty(ref _isTestViewOpen, value);
    }

    public string TestTargetHost
    {
        get => _testTargetHost;
        set => SetProperty(ref _testTargetHost, value);
    }

    public string TestTargetPort
    {
        get => _testTargetPort;
        set => SetProperty(ref _testTargetPort, value);
    }

    public string TestOutput
    {
        get => _testOutput;
        set => SetProperty(ref _testOutput, value);
    }

    public bool IsTesting
    {
        get => _isTesting;
        set => SetProperty(ref _isTesting, value);
    }

    public ICommand SaveCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand OpenTestCommand { get; }
    public ICommand CloseTestCommand { get; }
    public ICommand StartTestCommand { get; }

    private bool IsValidIpOrDomain(string input)
    {
        if (IPAddress.TryParse(input, out _))
        {
            return true;
        }

        var domainRegex = new Regex(@"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$");
        return domainRegex.IsMatch(input);
    }

    public ProxySettingsViewModel(string initialType, string initialIp, string initialPort, string initialUsername, string initialPassword, Action<string, string, string, string, string> onSave, Action onClose, Services.ProxyBridgeService? proxyService)
    {
        _onSave = onSave;
        _onClose = onClose;
        _proxyService = proxyService;

        ProxyType = initialType;
        ProxyIp = initialIp;
        ProxyPort = initialPort;
        ProxyUsername = initialUsername;
        ProxyPassword = initialPassword;

        SaveCommand = new RelayCommand(() =>
        {
            bool isValid = ValidationHelper.ValidateIpOrDomain(ProxyIp, IsValidIpOrDomain, msg => IpError = msg)
                && ValidationHelper.ValidatePort(ProxyPort, msg => PortError = msg);

            if (isValid)
            {
                _onSave?.Invoke(ProxyType, ProxyIp, ProxyPort, ProxyUsername ?? "", ProxyPassword ?? "");
            }
        });

        CancelCommand = new RelayCommand(() =>
        {
            _onClose?.Invoke();
        });

        OpenTestCommand = new RelayCommand(() =>
        {
            IsTestViewOpen = true;
            TestOutput = "";
        });

        CloseTestCommand = new RelayCommand(() =>
        {
            IsTestViewOpen = false;
        });

        StartTestCommand = new RelayCommand(async () =>
        {
            if (IsTesting) return;

            if (string.IsNullOrWhiteSpace(ProxyIp))
            {
                TestOutput = "ERROR: Please configure proxy IP address or hostname first";
                return;
            }

            if (!ushort.TryParse(ProxyPort, out ushort proxyPortNum))
            {
                TestOutput = "ERROR: Please configure valid proxy port first";
                return;
            }

            if (string.IsNullOrWhiteSpace(TestTargetHost))
            {
                TestOutput = "ERROR: Please enter target host";
                return;
            }

            if (!ushort.TryParse(TestTargetPort, out ushort targetPortNum))
            {
                TestOutput = "ERROR: Invalid target port";
                return;
            }

            IsTesting = true;
            TestOutput = "Testing connection...\n";

            try
            {
                if (_proxyService != null)
                {
                    _proxyService.SetProxyConfig(ProxyType, ProxyIp, proxyPortNum, ProxyUsername ?? "", ProxyPassword ?? "");

                    await System.Threading.Tasks.Task.Run(() =>
                    {
                        var result = _proxyService.TestConnection(TestTargetHost, targetPortNum);
                        TestOutput = result;
                    });
                }
                else
                {
                    TestOutput = "ERROR: Proxy service not available";
                }
            }
            catch (Exception ex)
            {
                TestOutput += $"\nERROR: {ex.Message}";
            }
            finally
            {
                IsTesting = false;
            }
        });
    }
}

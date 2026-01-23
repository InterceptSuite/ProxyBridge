using System;

namespace ProxyBridge.GUI.Common;

// handles common validation patterns
public static class ValidationHelper
{
    public static string DefaultIfEmpty(string value, string defaultValue = "*")
    {
        return string.IsNullOrWhiteSpace(value) ? defaultValue : value;
    }

    public static bool ValidateNotEmpty(string value, string errorMessage, Action<string> setError)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            setError(errorMessage);
            return false;
        }
        setError("");
        return true;
    }

    public static bool ValidatePort(string portStr, Action<string> setError)
    {
        if (string.IsNullOrWhiteSpace(portStr))
        {
            setError("Port is required");
            return false;
        }

        if (!int.TryParse(portStr, out int port) || port < 1 || port > 65535)
        {
            setError("Port must be between 1 and 65535");
            return false;
        }

        setError("");
        return true;
    }

    public static bool ValidateIpOrDomain(string value, Func<string, bool> validator, Action<string> setError)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            setError("IP address or hostname is required");
            return false;
        }

        if (!validator(value))
        {
            setError("Invalid IP address or hostname");
            return false;
        }

        setError("");
        return true;
    }
}

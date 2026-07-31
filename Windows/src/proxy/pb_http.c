#include "pb_internal.h"

// HTTP proxy: CONNECT tunnels (IPv4/IPv6).

int http_connect_v6(SOCKET s, const UINT8 dest_ip6[16], UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    char request[HTTP_BUFFER_SIZE];
    char response[4096];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    // Format IPv6 address as [addr]:port per RFC 2732
    char addr_str[64];
    inet_ntop(AF_INET6, dest_ip6, addr_str, sizeof(addr_str));

    // Use the cached hostname only if this config opts to let the proxy resolve DNS.
    char cached_domain[256];
    const char *host_part;
    char host_buf[270];  // big enough for [ipv6]:port or domain
    if (cfg != NULL && cfg->send_domain_to_proxy && dns_cache_lookup_v6(dest_ip6, cached_domain, sizeof(cached_domain)))
    {
        host_part = cached_domain;
        strncpy_s(host_buf, sizeof(host_buf), cached_domain, _TRUNCATE);
    }
    else
    {
        snprintf(host_buf, sizeof(host_buf), "[%s]", addr_str);
        host_part = host_buf;
    }

    if (use_auth)
    {
        char credentials[SOCKS5_BUFFER_SIZE], encoded[HTTP_BUFFER_SIZE];
        snprintf(credentials, sizeof(credentials), "%s:%s", cfg->username, cfg->password);
        base64_encode(credentials, encoded, sizeof(encoded));
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\n\r\n",
            host_part, dest_port, host_part, dest_port, encoded);
    }
    else
    {
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
            host_part, dest_port, host_part, dest_port);
    }

    if (send(s, request, len, 0) != len) return -1;

    len = recv(s, response, sizeof(response) - 1, 0);
    if (len <= 0 || len >= (int)sizeof(response)) return -1;
    response[len] = '\0';
    char *code_start = strchr(response, ' ');
    if (!code_start || atoi(code_start + 1) != 200) return -1;
    return 0;
}

int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    char request[HTTP_BUFFER_SIZE];
    char response[4096];
    int len;
    char *status_line;
    int status_code;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    // Use the cached hostname only if this config opts to let the proxy resolve DNS.
    char cached_domain[256];
    char ip_str[32];
    const char *host_part;
    if (cfg != NULL && cfg->send_domain_to_proxy && dns_cache_lookup(dest_ip, cached_domain, sizeof(cached_domain)))
    {
        host_part = cached_domain;
    }
    else
    {
        format_ip_address(dest_ip, ip_str, sizeof(ip_str));
        host_part = ip_str;
    }

    if (use_auth)
    {
        // Create "username:password" string and encode as Base64
        char credentials[SOCKS5_BUFFER_SIZE];
        char encoded[HTTP_BUFFER_SIZE];
        snprintf(credentials, sizeof(credentials), "%s:%s", cfg->username, cfg->password);
        base64_encode(credentials, encoded, sizeof(encoded));

        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            host_part, dest_port, host_part, dest_port, encoded);
    }
    else
    {
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            host_part, dest_port, host_part, dest_port);
    }

    if (send(s, request, len, 0) != len)
    {
        log_message("HTTP: Failed to send CONNECT request");
        return -1;
    }

    len = recv(s, response, sizeof(response) - 1, 0);
    if (len <= 0 || len >= (int)sizeof(response))
    {
        log_message("HTTP: Failed to receive response");
        return -1;
    }
    response[len] = '\0';

    status_line = response;
    if (strncmp(status_line, "HTTP/1.", 7) != 0)
    {
        log_message("HTTP: Invalid response format");
        return -1;
    }

    status_code = 0;
    char *code_start = strchr(status_line, ' ');
    if (code_start != NULL)
        status_code = atoi(code_start + 1);

    if (status_code != 200)
    {
        log_message("HTTP: CONNECT failed with status %d", status_code);
        return -1;
    }

    return 0;
}


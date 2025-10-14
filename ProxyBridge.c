/*
 * ProxyBridge - Transparent SOCKS5 Traffic Redirector for Windows
 *
 * Copyright (c) 2025 Anof-cyber/ InterceptSuite
 * https://github.com/InterceptSuite/ProxyBridge
 *
 * This program redirects TCP traffic through a SOCKS5 proxy transparently
 * using WinDivert packet interception. Works with any protocol (HTTP, HTTPS,
 * databases, RDP, etc.) without application configuration.
 *
 * The Code is updated version of https://reqrypt.org/samples/streamdump.html
 */

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#pragma comment(lib, "iphlpapi.lib")

// Configuration
#define MAXBUF          0xFFFF
#define DEFAULT_SOCKS5_IP  "127.0.0.1"
#define DEFAULT_SOCKS5_PORT 4444
#define LOCAL_PROXY_PORT 34010  // DO NOT EDIT, For some stupid reason other ports are detected as malware by #fuck Windows
#define MAX_PROCESS_NAME 256
#define MAX_PROXY_URL 512

// Proxy types
typedef enum {
    PROXY_TYPE_SOCKS5,
    PROXY_TYPE_HTTP
} PROXY_TYPE;

// SOCKS5 protocol constants
#define SOCKS5_VERSION      0x05
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_ATYP_IPV4    0x01
#define SOCKS5_AUTH_NONE    0x00

// Connection tracking
typedef struct CONNECTION_INFO {
    UINT16 src_port;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

static CONNECTION_INFO *connection_list = NULL;

// Structures
typedef struct {
    UINT16 local_proxy_port;
    char target_process[MAX_PROCESS_NAME];
    char proxy_ip[64];
    UINT16 proxy_port;
} PROXY_CONFIG;

typedef struct {
    SOCKET client_socket;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
} CONNECTION_CONFIG;

typedef struct {
    SOCKET from_socket;
    SOCKET to_socket;
} TRANSFER_CONFIG;

// Global
static HANDLE lock;

static char g_proxy_ip[64] = DEFAULT_SOCKS5_IP;
static UINT16 g_proxy_port = DEFAULT_SOCKS5_PORT;
static UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
static PROXY_TYPE g_proxy_type = PROXY_TYPE_SOCKS5;

// Function prototypes
static UINT32 parse_ipv4(const char *ip);
static BOOL parse_proxy_url(const char *url, char *ip, UINT16 *port, PROXY_TYPE *type);
static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static DWORD WINAPI local_proxy_server(LPVOID arg);
static DWORD WINAPI connection_handler(LPVOID arg);
static DWORD WINAPI transfer_handler(LPVOID arg);
static DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port);
static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);
static BOOL is_target_process(UINT32 src_ip, UINT16 src_port, const char *target_name);
static void add_connection(UINT16 src_port, UINT32 dest_ip, UINT16 dest_port);
static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port);
static void remove_connection(UINT16 src_port);

// Logging
static void message(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    WaitForSingleObject(lock, INFINITE);
    vfprintf(stderr, msg, args);
    putc('\n', stderr);
    ReleaseMutex(lock);
    va_end(args);
}

#define error(msg, ...)                         \
    do {                                        \
        message("ERROR: " msg, ## __VA_ARGS__); \
        exit(EXIT_FAILURE);                     \
    } while (0)

#define warning(msg, ...)                       \
    message("WARNING: " msg, ## __VA_ARGS__)


int main(int argc, char **argv)
{
    HANDLE handle, proxy_thread;
    char filter[512];
    INT16 priority = 123;
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;
    PROXY_CONFIG *config;
    char exclude_process[MAX_PROCESS_NAME] = {0};
    BOOL use_exclude = FALSE;
    char target_process[MAX_PROCESS_NAME] = {0};
    int i;

    if (argc < 2)
    {
        fprintf(stderr, "\n");
        fprintf(stderr, "  ____                        ____       _     _            \n");
        fprintf(stderr, " |  _ \\ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___ \n");
        fprintf(stderr, " | |_) | '__/ _ \\ \\/ / | | | |  _ \\| '__| |/ _` |/ _` |/ _ \\\n");
        fprintf(stderr, " |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/\n");
        fprintf(stderr, " |_|   |_|  \\___/_/\\_\\\\__, | |____/|_|  |_|\\__,_|\\__, |\\___|\n");
        fprintf(stderr, "                      |___/                      |___/       \n");
        fprintf(stderr, "\tAuthor: Sourav Kalal/InterceptSuite\n");
        fprintf(stderr, "\tProject: https://github.com/InterceptSuite/ProxyBridge\n\n");
        fprintf(stderr, "Usage: %s <process-name.exe> [OPTIONS]\n\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  --proxy <url>         Proxy URL (default: socks5://127.0.0.1:4444)\n");
        fprintf(stderr, "                        Supported: socks5://host:port, http://host:port\n");
        fprintf(stderr, "  --relay-port <port>   Local relay port (default: 37123)\n");
        fprintf(stderr, "  --exclude <process>   Exclude process from redirection\n\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s chrome.exe\n", argv[0]);
        fprintf(stderr, "  %s firefox.exe --proxy socks5://127.0.0.1:9050\n", argv[0]);
        fprintf(stderr, "  %s chrome.exe --proxy http://127.0.0.1:8080\n", argv[0]);
        fprintf(stderr, "  %s chrome.exe --exclude InterceptSuite.exe\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    strncpy(target_process, argv[1], MAX_PROCESS_NAME - 1);
    target_process[MAX_PROCESS_NAME - 1] = '\0';

    for (i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--proxy") == 0 && i + 1 < argc)
        {
            if (!parse_proxy_url(argv[i + 1], g_proxy_ip, &g_proxy_port, &g_proxy_type))
            {
                error("Invalid proxy URL: %s", argv[i + 1]);
            }
            i++;
        }
        else if (strcmp(argv[i], "--relay-port") == 0 && i + 1 < argc)
        {
            int port = atoi(argv[i + 1]);
            if (port <= 0 || port > 65535)
            {
                error("Invalid relay port: %s (must be 1-65535)", argv[i + 1]);
            }
            g_local_relay_port = (UINT16)port;
            i++;
        }
        else if (strcmp(argv[i], "--exclude") == 0 && i + 1 < argc)
        {
            strncpy(exclude_process, argv[i + 1], MAX_PROCESS_NAME - 1);
            exclude_process[MAX_PROCESS_NAME - 1] = '\0';
            use_exclude = TRUE;
            i++;
        }
    }

    lock = CreateMutex(NULL, FALSE, NULL);
    if (lock == NULL)
    {
        error("Failed to create mutex (%lu)", GetLastError());
    }

    // Start local proxy server
    config = (PROXY_CONFIG *)malloc(sizeof(PROXY_CONFIG));
    if (config == NULL)
    {
        error("Failed to allocate memory");
    }
    strncpy(config->target_process, target_process, MAX_PROCESS_NAME - 1);
    config->local_proxy_port = g_local_relay_port;

    proxy_thread = CreateThread(NULL, 1, local_proxy_server, (LPVOID)config, 0, NULL);
    if (proxy_thread == NULL)
    {
        error("Failed to create proxy thread (%lu)", GetLastError());
    }
    CloseHandle(proxy_thread);

    Sleep(500);  // Wait for proxy to start   - Should not edit the time

    // Build WinDivert filter - capture all TCP traffic to/from local proxy port
    // need both outbound (to check process) and inbound (return traffic from proxy)
    snprintf(filter, sizeof(filter),
        "tcp and (outbound or (tcp.DstPort == %d or tcp.SrcPort == %d))",
        g_local_relay_port, g_local_relay_port);

    message("ProxyBridge started");
    message("Local relay: localhost:%d", g_local_relay_port);
    message("%s proxy: %s:%d", g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
            g_proxy_ip, g_proxy_port);
    message("Redirecting traffic from: %s", target_process);
    if (use_exclude)
    {
        message("Excluding process: %s (direct connection)", exclude_process);
    }

    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        error("Failed to open WinDivert (%lu)", GetLastError());
    }

    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);

    // Main packet processing loop
    while (TRUE)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            warning("Failed to receive packet (%lu)", GetLastError());
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL,
            NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL);

        if (ip_header == NULL || tcp_header == NULL)
        {
            continue;
        }

        if (addr.Outbound)
        {
            // Check if we should exclude this process (proxy app)
            if (use_exclude)
            {
                if (is_target_process(ip_header->SrcAddr, ntohs(tcp_header->SrcPort), exclude_process))
                {
                    // Excluded process - forward unchanged
                    WinDivertSend(handle, packet, packet_len, NULL, &addr);
                    continue;
                }
            }

            // Check if this is traffic FROM local proxy going back to target process
            if (tcp_header->SrcPort == htons(g_local_relay_port))
            {
                // This is return traffic from local proxy
                // Need to restore original source port for the connection
                // Need to figure out UDP case to handle connection
                UINT16 dst_port = ntohs(tcp_header->DstPort);
                UINT32 orig_dest_ip;
                UINT16 orig_dest_port;

                if (get_connection(dst_port, &orig_dest_ip, &orig_dest_port))
                {
                    tcp_header->SrcPort = htons(orig_dest_port);
                }

                // Reflect it back
                UINT32 temp_addr = ip_header->DstAddr;
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;

                // Remove connection if this is FIN or RST
                if (tcp_header->Fin || tcp_header->Rst)
                {
                    remove_connection(dst_port);
                }
            }
            // Check if this is from our target process going OUT
            else if (is_target_process(ip_header->SrcAddr, ntohs(tcp_header->SrcPort), target_process))
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);
                UINT32 orig_dest_ip = ip_header->DstAddr;
                UINT16 orig_dest_port = ntohs(tcp_header->DstPort);

                // Track this connection if it's a SYN
                // Need to Figure out this, for some reasonn curl fails
                if (tcp_header->Syn && !tcp_header->Ack)
                {
                    add_connection(src_port, orig_dest_ip, orig_dest_port);
                }

                // redirect to local proxy by reflecting the packet
                UINT32 temp_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(g_local_relay_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;
            }
            else
            {
                // not our target process, forward unchanged
                WinDivertSend(handle, packet, packet_len, NULL, &addr);
                continue;
            }
        }
        else
        {
            // Inbound traffic - check if it's TO local proxy (from target process)
            if (tcp_header->DstPort == htons(g_local_relay_port))
            {
                // traffic going to local proxy

            }
            else
            {
                // other inbound traffic, forward unchanged
                WinDivertSend(handle, packet, packet_len, NULL, &addr);
                continue;
            }
        }

        WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
        if (!WinDivertSend(handle, packet, packet_len, NULL, &addr))
        {
            warning("Failed to send packet (%lu)", GetLastError());
        }
    }

    return 0;
}


static UINT32 parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    {
        return 0;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255)
    {
        return 0;
    }
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}


static BOOL parse_proxy_url(const char *url, char *ip, UINT16 *port, PROXY_TYPE *type)
{
    char temp_url[MAX_PROXY_URL];
    char *protocol, *host, *port_str;

    if (url == NULL || ip == NULL || port == NULL || type == NULL)
    {
        return FALSE;
    }

    if (strlen(url) >= MAX_PROXY_URL)
    {
        return FALSE;
    }

    strncpy(temp_url, url, MAX_PROXY_URL - 1);
    temp_url[MAX_PROXY_URL - 1] = '\0';

    protocol = temp_url;
    if (strncmp(protocol, "socks5://", 9) == 0)
    {
        *type = PROXY_TYPE_SOCKS5;
        host = protocol + 9;
    }
    else if (strncmp(protocol, "socks://", 8) == 0)
    {
        *type = PROXY_TYPE_SOCKS5;
        host = protocol + 8;
    }
    else if (strncmp(protocol, "http://", 7) == 0)
    {
        *type = PROXY_TYPE_HTTP;
        host = protocol + 7;
    }
    else
    {
        // Default to SOCKS5 if no protocol specified
        *type = PROXY_TYPE_SOCKS5;
        host = protocol;
    }

    port_str = strrchr(host, ':');
    if (port_str == NULL)
    {
        return FALSE;
    }

    *port_str = '\0';
    port_str++;

    int port_num = atoi(port_str);
    if (port_num <= 0 || port_num > 65535)
    {
        return FALSE;
    }
    *port = (UINT16)port_num;

    strncpy(ip, host, 63);
    ip[63] = '\0';

    return TRUE;
}

static DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port)
{
    MIB_TCPTABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0;
    DWORD pid = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
    {
        return 0;
    }

    tcp_table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (tcp_table == NULL)
    {
        return 0;
    }

    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
    {
        free(tcp_table);
        return 0;
    }

    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++)
    {
        MIB_TCPROW_OWNER_PID *row = &tcp_table->table[i];

        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port)
        {
            pid = row->dwOwningPid;
            break;
        }
    }

    free(tcp_table);
    return pid;
}


static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size)
{
    HANDLE hProcess;
    char full_path[MAX_PATH];
    DWORD path_len = MAX_PATH;

    if (pid == 0)
    {
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL)
    {
        return FALSE;
    }

    if (QueryFullProcessImageNameA(hProcess, 0, full_path, &path_len))
    {
        char *filename = strrchr(full_path, '\\');
        if (filename != NULL)
        {
            filename++;
            strncpy(name, filename, name_size - 1);
            name[name_size - 1] = '\0';
            CloseHandle(hProcess);
            return TRUE;
        }
    }

    CloseHandle(hProcess);
    return FALSE;
}


static BOOL is_target_process(UINT32 src_ip, UINT16 src_port, const char *target_name)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];
    char target_with_exe[MAX_PROCESS_NAME];
    char target_without_exe[MAX_PROCESS_NAME];

    pid = get_process_id_from_connection(src_ip, src_port);
    if (pid == 0)
    {
        return FALSE;
    }

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
    {
        return FALSE;
    }

    strncpy(target_without_exe, target_name, MAX_PROCESS_NAME - 1);
    target_without_exe[MAX_PROCESS_NAME - 1] = '\0';

    char *dot = strrchr(target_without_exe, '.');
    if (dot && _stricmp(dot, ".exe") == 0)
    {
        *dot = '\0';
    }

    if (strrchr(target_name, '.') == NULL)
    {
        snprintf(target_with_exe, MAX_PROCESS_NAME, "%s.exe", target_name);
    }
    else
    {
        strncpy(target_with_exe, target_name, MAX_PROCESS_NAME - 1);
    }

    if (_stricmp(process_name, target_name) == 0 ||
        _stricmp(process_name, target_with_exe) == 0 ||
        _stricmp(process_name, target_without_exe) == 0)
    {
        static BOOL first_match = TRUE;
        if (first_match)
        {
            message("Detected target process: %s (PID: %lu) on port %d",
                    process_name, pid, src_port);
            first_match = FALSE;
        }
        return TRUE;
    }

    return FALSE;
}


static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port)
{
    unsigned char buf[512];
    int len;

    message("SOCKS5: Connecting to %d.%d.%d.%d:%d",
        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);

    // Step 1: Authentication method selection
    buf[0] = SOCKS5_VERSION;
    buf[1] = 0x01;
    buf[2] = SOCKS5_AUTH_NONE;
    if (send(s, (char*)buf, 3, 0) != 3)
    {
        warning("SOCKS5: Failed to send auth methods");
        return -1;
    }

    // Step 2: Receive authentication response
    len = recv(s, (char*)buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_AUTH_NONE)
    {
        warning("SOCKS5: Auth method rejected");
        return -1;
    }

    // Step 3: Send CONNECT request
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = (dest_ip >> 0) & 0xFF;
    buf[5] = (dest_ip >> 8) & 0xFF;
    buf[6] = (dest_ip >> 16) & 0xFF;
    buf[7] = (dest_ip >> 24) & 0xFF;
    buf[8] = (dest_port >> 8) & 0xFF;
    buf[9] = (dest_port >> 0) & 0xFF;

    if (send(s, (char*)buf, 10, 0) != 10)
    {
        warning("SOCKS5: Failed to send CONNECT");
        return -1;
    }

    // Step 4: Receive CONNECT response
    len = recv(s, (char*)buf, 10, 0);
    if (len < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
    {
        warning("SOCKS5: CONNECT failed (reply=%d)", len > 1 ? buf[1] : -1);
        return -1;
    }

    message("SOCKS5: Connection established");
    return 0;
}


static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port)
{
    char request[512];
    char response[4096];
    int len;
    char *status_line;
    int status_code;

    message("HTTP: Connecting to %d.%d.%d.%d:%d",
        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);

    len = snprintf(request, sizeof(request),
        "CONNECT %d.%d.%d.%d:%d HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d:%d\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "\r\n",
        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);


    if (send(s, request, len, 0) != len)
    {
        warning("HTTP: Failed to send CONNECT request");
        return -1;
    }

    len = recv(s, response, sizeof(response) - 1, 0);
    if (len <= 0)
    {
        warning("HTTP: Failed to receive response");
        return -1;
    }
    response[len] = '\0';

    status_line = response;
    if (strncmp(status_line, "HTTP/1.", 7) != 0)
    {
        warning("HTTP: Invalid response format");
        return -1;
    }

    status_code = 0;
    char *code_start = strchr(status_line, ' ');
    if (code_start != NULL)
    {
        status_code = atoi(code_start + 1);
    }

    if (status_code != 200)
    {
        warning("HTTP: CONNECT failed with status %d", status_code);
        return -1;
    }

    message("HTTP: Connection established");
    return 0;
}


static DWORD WINAPI local_proxy_server(LPVOID arg)
{
    PROXY_CONFIG *config = (PROXY_CONFIG *)arg;
    UINT16 local_port = config->local_proxy_port;
    WSADATA wsa_data;
    struct sockaddr_in addr;
    SOCKET listen_sock;
    int on = 1;

    free(config);

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        error("WSAStartup failed (%lu)", GetLastError());
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        error("Socket creation failed (%d)", WSAGetLastError());
    }

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_port);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        error("Bind failed (%d)", WSAGetLastError());
    }

    if (listen(listen_sock, 16) == SOCKET_ERROR)
    {
        error("Listen failed (%d)", WSAGetLastError());
    }

    message("Local proxy listening on port %d", local_port);

    while (TRUE)
    {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock == INVALID_SOCKET)
        {
            warning("Accept failed (%d)", WSAGetLastError());
            continue;
        }

        CONNECTION_CONFIG *conn_config = (CONNECTION_CONFIG *)malloc(sizeof(CONNECTION_CONFIG));
        if (conn_config == NULL)
        {
            closesocket(client_sock);
            continue;
        }

        conn_config->client_socket = client_sock;


        UINT16 client_port = ntohs(client_addr.sin_port);
        if (!get_connection(client_port, &conn_config->orig_dest_ip, &conn_config->orig_dest_port))
        {

            warning("Connection from port %d not found in tracking table", client_port);
            closesocket(client_sock);
            free(conn_config);
            continue;
        }

        HANDLE conn_thread = CreateThread(NULL, 1, connection_handler,
                                          (LPVOID)conn_config, 0, NULL);
        if (conn_thread == NULL)
        {
            warning("CreateThread failed (%lu)", GetLastError());
            closesocket(client_sock);
            free(conn_config);
            continue;
        }
        CloseHandle(conn_thread);
    }

    return 0;
}


static DWORD WINAPI connection_handler(LPVOID arg)
{
    CONNECTION_CONFIG *config = (CONNECTION_CONFIG *)arg;
    SOCKET client_sock = config->client_socket;
    UINT32 dest_ip = config->orig_dest_ip;
    UINT16 dest_port = config->orig_dest_port;
    SOCKET socks_sock;
    struct sockaddr_in socks_addr;
    UINT32 socks5_ip;

    free(config);

    // Connect to SOCKS5 proxy
    socks5_ip = parse_ipv4(g_proxy_ip);
    socks_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (socks_sock == INVALID_SOCKET)
    {
        warning("Socket creation failed (%d)", WSAGetLastError());
        closesocket(client_sock);
        return 0;
    }

    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(g_proxy_port);

    if (connect(socks_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        warning("Failed to connect to proxy (%d)", WSAGetLastError());
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        if (socks5_connect(socks_sock, dest_ip, dest_port) != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }
    else if (g_proxy_type == PROXY_TYPE_HTTP)
    {
        if (http_connect(socks_sock, dest_ip, dest_port) != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }

    // Create bidirectional forwarding threads
    TRANSFER_CONFIG *config1 = (TRANSFER_CONFIG *)malloc(sizeof(TRANSFER_CONFIG));
    TRANSFER_CONFIG *config2 = (TRANSFER_CONFIG *)malloc(sizeof(TRANSFER_CONFIG));

    if (config1 == NULL || config2 == NULL)
    {
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    config1->from_socket = client_sock;
    config1->to_socket = socks_sock;
    config2->from_socket = socks_sock;
    config2->to_socket = client_sock;

    HANDLE thread1 = CreateThread(NULL, 1, transfer_handler, (LPVOID)config1, 0, NULL);
    if (thread1 == NULL)
    {
        warning("CreateThread failed (%lu)", GetLastError());
        closesocket(client_sock);
        closesocket(socks_sock);
        free(config1);
        free(config2);
        return 0;
    }

    transfer_handler((LPVOID)config2);
    WaitForSingleObject(thread1, INFINITE);
    CloseHandle(thread1);

    closesocket(client_sock);
    closesocket(socks_sock);

    return 0;
}

/*
 * Transfer handler thread - forwards data bidirectionally
 */
static DWORD WINAPI transfer_handler(LPVOID arg)
{
    TRANSFER_CONFIG *config = (TRANSFER_CONFIG *)arg;
    SOCKET from = config->from_socket;
    SOCKET to = config->to_socket;
    char buf[8192];
    int len;

    free(config);

    while (TRUE)
    {
        len = recv(from, buf, sizeof(buf), 0);
        if (len <= 0)
        {
            shutdown(from, SD_RECEIVE);
            shutdown(to, SD_SEND);
            break;
        }

        int sent = 0;
        while (sent < len)
        {
            int n = send(to, buf + sent, len - sent, 0);
            if (n == SOCKET_ERROR)
            {
                shutdown(from, SD_BOTH);
                shutdown(to, SD_BOTH);
                return 0;
            }
            sent += n;
        }
    }

    return 0;
}

/*
 * Add connection to tracking list
 */
static void add_connection(UINT16 src_port, UINT32 dest_ip, UINT16 dest_port)
{
    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL)
    {
        return;
    }

    conn->src_port = src_port;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;

    WaitForSingleObject(lock, INFINITE);
    conn->next = connection_list;
    connection_list = conn;
    ReleaseMutex(lock);
}

/*
 * Get connection info from tracking list
 */
static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port)
{
    BOOL found = FALSE;

    WaitForSingleObject(lock, INFINITE);
    CONNECTION_INFO *conn = connection_list;
    while (conn != NULL)
    {
        if (conn->src_port == src_port)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseMutex(lock);

    return found;
}

/*
 * Remove connection from tracking list
 */
static void remove_connection(UINT16 src_port)
{
    WaitForSingleObject(lock, INFINITE);
    CONNECTION_INFO **conn_ptr = &connection_list;
    while (*conn_ptr != NULL)
    {
        if ((*conn_ptr)->src_port == src_port)
        {
            CONNECTION_INFO *to_free = *conn_ptr;
            *conn_ptr = (*conn_ptr)->next;
            free(to_free);
            break;
        }
        conn_ptr = &(*conn_ptr)->next;
    }
    ReleaseMutex(lock);
}
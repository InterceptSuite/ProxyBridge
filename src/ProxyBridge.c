#include <winsock2.h>
#include <windows.h>
#include "ProxyBridge.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAXBUF 0xFFFF
#define DEFAULT_SOCKS5_IP "127.0.0.1"
#define DEFAULT_SOCKS5_PORT 4444
#define LOCAL_PROXY_PORT 34010
#define MAX_PROCESS_NAME 256

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_AUTH_NONE 0x00

typedef struct CONNECTION_INFO {
    UINT16 src_port;
    UINT32 src_ip;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
    BOOL is_tracked;
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

typedef struct {
    SOCKET client_socket;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
} CONNECTION_CONFIG;

typedef struct {
    SOCKET from_socket;
    SOCKET to_socket;
} TRANSFER_CONFIG;

static CONNECTION_INFO *connection_list = NULL;
static HANDLE lock = NULL;
static HANDLE windivert_handle = INVALID_HANDLE_VALUE;
static HANDLE packet_thread = NULL;
static HANDLE proxy_thread = NULL;
static BOOL running = FALSE;

static char g_target_process[MAX_PROCESS_NAME] = "";
static char g_exclude_process[MAX_PROCESS_NAME] = "";
static char g_proxy_ip[64] = DEFAULT_SOCKS5_IP;
static UINT16 g_proxy_port = DEFAULT_SOCKS5_PORT;
static UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
static ProxyType g_proxy_type = PROXY_TYPE_SOCKS5;
static BOOL g_use_exclude = FALSE;
static LogCallback g_log_callback = NULL;
static ConnectionCallback g_connection_callback = NULL;

static void log_message(const char *msg, ...)
{
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    g_log_callback(buffer);
}

static UINT32 parse_ipv4(const char *ip);
static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static DWORD WINAPI local_proxy_server(LPVOID arg);
static DWORD WINAPI connection_handler(LPVOID arg);
static DWORD WINAPI transfer_handler(LPVOID arg);
static DWORD WINAPI packet_processor(LPVOID arg);
static DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port);
static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);
static BOOL is_target_process(UINT32 src_ip, UINT16 src_port, const char *target_name);
static void add_connection(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port);
static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port);
static BOOL is_connection_tracked(UINT16 src_port);
static void remove_connection(UINT16 src_port);


static DWORD WINAPI packet_processor(LPVOID arg)
{
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;

    while (running)
    {
        if (!WinDivertRecv(windivert_handle, packet, sizeof(packet), &packet_len, &addr))
        {
            if (GetLastError() == ERROR_INVALID_HANDLE)
                break;
            log_message("Failed to receive packet (%lu)", GetLastError());
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL,
            NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL);

        if (ip_header == NULL || tcp_header == NULL)
            continue;

        if (addr.Outbound)
        {
            if (g_use_exclude)
            {
                if (is_target_process(ip_header->SrcAddr, ntohs(tcp_header->SrcPort), g_exclude_process))
                {
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }
            }

            if (tcp_header->SrcPort == htons(g_local_relay_port))
            {
                UINT16 dst_port = ntohs(tcp_header->DstPort);
                UINT32 orig_dest_ip;
                UINT16 orig_dest_port;

                if (get_connection(dst_port, &orig_dest_ip, &orig_dest_port))
                    tcp_header->SrcPort = htons(orig_dest_port);

                UINT32 temp_addr = ip_header->DstAddr;
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;

                if (tcp_header->Fin || tcp_header->Rst)
                    remove_connection(dst_port);
            }
            else if (is_connection_tracked(ntohs(tcp_header->SrcPort)))
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);

                if (tcp_header->Fin || tcp_header->Rst)
                    remove_connection(src_port);

                UINT32 temp_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(g_local_relay_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;
            }
            else if (is_target_process(ip_header->SrcAddr, ntohs(tcp_header->SrcPort), g_target_process))
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);
                UINT32 src_ip = ip_header->SrcAddr;
                UINT32 orig_dest_ip = ip_header->DstAddr;
                UINT16 orig_dest_port = ntohs(tcp_header->DstPort);

                add_connection(src_port, src_ip, orig_dest_ip, orig_dest_port);

                if (g_connection_callback != NULL)
                {
                    char process_name[MAX_PROCESS_NAME];
                    DWORD pid = get_process_id_from_connection(src_ip, src_port);
                    if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
                    {
                        char dest_ip_str[32];
                        snprintf(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
                            (orig_dest_ip >> 0) & 0xFF, (orig_dest_ip >> 8) & 0xFF,
                            (orig_dest_ip >> 16) & 0xFF, (orig_dest_ip >> 24) & 0xFF);
                        g_connection_callback(process_name, pid, src_port, dest_ip_str, orig_dest_port);
                    }
                }

                UINT32 temp_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(g_local_relay_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;
            }
            else
            {
                WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }
        }
        else
        {
            if (tcp_header->DstPort != htons(g_local_relay_port))
            {
                WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }
        }

        WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
        if (!WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr))
        {
            log_message("Failed to send packet (%lu)", GetLastError());
        }
    }

    return 0;
}

static UINT32 parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
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
            log_message("Detected target process: %s (PID: %lu) on port %d",
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

    log_message("SOCKS5: Connecting to %d.%d.%d.%d:%d",
        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);

    buf[0] = SOCKS5_VERSION;
    buf[1] = 0x01;
    buf[2] = SOCKS5_AUTH_NONE;
    if (send(s, (char*)buf, 3, 0) != 3)
    {
        log_message("SOCKS5: Failed to send auth methods");
        return -1;
    }

    len = recv(s, (char*)buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_AUTH_NONE)
    {
        log_message("SOCKS5: Auth method rejected");
        return -1;
    }

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
        log_message("SOCKS5: Failed to send CONNECT");
        return -1;
    }

    len = recv(s, (char*)buf, 10, 0);
    if (len < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
    {
        log_message("SOCKS5: CONNECT failed (reply=%d)", len > 1 ? buf[1] : -1);
        return -1;
    }

    log_message("SOCKS5: Connection established");
    return 0;
}


static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port)
{
    char request[512];
    char response[4096];
    int len;
    char *status_line;
    int status_code;

    log_message("HTTP: Connecting to %d.%d.%d.%d:%d",
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
        log_message("HTTP: Failed to send CONNECT request");
        return -1;
    }

    len = recv(s, response, sizeof(response) - 1, 0);
    if (len <= 0)
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

    log_message("HTTP: Connection established");
    return 0;
}


static DWORD WINAPI local_proxy_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in addr;
    SOCKET listen_sock;
    int on = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        log_message("WSAStartup failed (%lu)", GetLastError());
        return 1;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        log_message("Socket creation failed (%d)", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(g_local_relay_port);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        log_message("Bind failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    if (listen(listen_sock, 16) == SOCKET_ERROR)
    {
        log_message("Listen failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    log_message("Local proxy listening on port %d", g_local_relay_port);

    while (running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        struct timeval timeout = {1, 0};

        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock == INVALID_SOCKET)
            continue;

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
            log_message("Connection from port %d not found in tracking table", client_port);
            closesocket(client_sock);
            free(conn_config);
            continue;
        }

        HANDLE conn_thread = CreateThread(NULL, 1, connection_handler,
                                          (LPVOID)conn_config, 0, NULL);
        if (conn_thread == NULL)
        {
            log_message("CreateThread failed (%lu)", GetLastError());
            closesocket(client_sock);
            free(conn_config);
            continue;
        }
        CloseHandle(conn_thread);
    }

    closesocket(listen_sock);
    WSACleanup();
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
        log_message("Socket creation failed (%d)", WSAGetLastError());
        closesocket(client_sock);
        return 0;
    }

    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(g_proxy_port);

    if (connect(socks_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        log_message("Failed to connect to proxy (%d)", WSAGetLastError());
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
        log_message("CreateThread failed (%lu)", GetLastError());
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

static void add_connection(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port)
{
    WaitForSingleObject(lock, INFINITE);

    // Check if already exists
    CONNECTION_INFO *existing = connection_list;
    while (existing != NULL) {
        if (existing->src_port == src_port) {
            // Update existing entry
            existing->src_ip = src_ip;
            existing->orig_dest_ip = dest_ip;
            existing->orig_dest_port = dest_port;
            existing->is_tracked = TRUE;
            ReleaseMutex(lock);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseMutex(lock);
        return;
    }

    conn->src_port = src_port;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;
    conn->is_tracked = TRUE;
    conn->next = connection_list;
    connection_list = conn;
    ReleaseMutex(lock);
}

static BOOL is_connection_tracked(UINT16 src_port)
{
    BOOL tracked = FALSE;
    WaitForSingleObject(lock, INFINITE);
    CONNECTION_INFO *conn = connection_list;
    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_tracked) {
            tracked = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseMutex(lock);
    return tracked;
}

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

PROXYBRIDGE_API BOOL ProxyBridge_SetConfig(const ProxyBridgeConfig* config)
{
    if (running || config == NULL)
        return FALSE;

    g_log_callback = config->log_callback;
    g_connection_callback = config->connection_callback;

    if (config->target_process && config->target_process[0] != '\0')
    {
        strncpy(g_target_process, config->target_process, MAX_PROCESS_NAME - 1);
        g_target_process[MAX_PROCESS_NAME - 1] = '\0';
    }

    if (config->exclude_process && config->exclude_process[0] != '\0')
    {
        strncpy(g_exclude_process, config->exclude_process, MAX_PROCESS_NAME - 1);
        g_exclude_process[MAX_PROCESS_NAME - 1] = '\0';
        g_use_exclude = TRUE;
    }

    return TRUE;
}

PROXYBRIDGE_API BOOL ProxyBridge_Start(void)
{
    char filter[512];
    INT16 priority = 123;

    if (running)
        return FALSE;

    if (lock == NULL)
    {
        lock = CreateMutex(NULL, FALSE, NULL);
        if (lock == NULL)
            return FALSE;
    }

    running = TRUE;

    proxy_thread = CreateThread(NULL, 1, local_proxy_server, NULL, 0, NULL);
    if (proxy_thread == NULL)
    {
        running = FALSE;
        return FALSE;
    }

    Sleep(500);

    snprintf(filter, sizeof(filter),
        "tcp and (outbound or (tcp.DstPort == %d or tcp.SrcPort == %d))",
        g_local_relay_port, g_local_relay_port);

    windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
    if (windivert_handle == INVALID_HANDLE_VALUE)
    {
        log_message("Failed to open WinDivert (%lu)", GetLastError());
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);

    packet_thread = CreateThread(NULL, 1, packet_processor, NULL, 0, NULL);
    if (packet_thread == NULL)
    {
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    log_message("ProxyBridge started");
    log_message("Local relay: localhost:%d", g_local_relay_port);
    log_message("%s proxy: %s:%d", g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5", g_proxy_ip, g_proxy_port);

    if (g_target_process[0] != '\0')
        log_message("Redirecting traffic from: %s", g_target_process);
    else
        log_message("No target process set - checking all connections");

    if (g_use_exclude)
        log_message("Excluding process: %s (direct connection)", g_exclude_process);

    return TRUE;
}

PROXYBRIDGE_API BOOL ProxyBridge_Stop(void)
{
    if (!running)
        return FALSE;

    running = FALSE;

    if (windivert_handle != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }

    if (packet_thread != NULL)
    {
        WaitForSingleObject(packet_thread, 5000);
        CloseHandle(packet_thread);
        packet_thread = NULL;
    }

    if (proxy_thread != NULL)
    {
        WaitForSingleObject(proxy_thread, 5000);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
    }

    WaitForSingleObject(lock, INFINITE);
    while (connection_list != NULL)
    {
        CONNECTION_INFO *to_free = connection_list;
        connection_list = connection_list->next;
        free(to_free);
    }
    ReleaseMutex(lock);

    log_message("ProxyBridge stopped");

    return TRUE;
}

PROXYBRIDGE_API BOOL ProxyBridge_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port)
{
    if (running || proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return FALSE;

    if (parse_ipv4(proxy_ip) == 0)
        return FALSE;

    strncpy(g_proxy_ip, proxy_ip, sizeof(g_proxy_ip) - 1);
    g_proxy_ip[sizeof(g_proxy_ip) - 1] = '\0';
    g_proxy_port = proxy_port;
    g_proxy_type = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            if (running)
                ProxyBridge_Stop();
            if (lock != NULL)
            {
                CloseHandle(lock);
                lock = NULL;
            }
            break;
    }
    return TRUE;
}
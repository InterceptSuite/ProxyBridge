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
#define SOCKS5_PROXY_IP  "127.0.0.1"
#define SOCKS5_PROXY_PORT 4444
#define LOCAL_PROXY_PORT 34010
#define MAX_PROCESS_NAME 256

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

// Function prototypes
static UINT32 parse_ipv4(const char *ip);
static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
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
    DWORD exclude_pid = 0;
    BOOL use_exclude_pid = FALSE;
    char target_process[MAX_PROCESS_NAME] = {0};

    if (argc < 2 || argc > 4)
    {
        fprintf(stderr, "ProxyBridge - Transparent SOCKS5 Traffic Redirector\n\n");
        fprintf(stderr, "Usage: %s <process-name.exe> [-pid <exclude-process-id>]\n\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s chrome.exe           - Redirect all chrome.exe traffic\n", argv[0]);
        fprintf(stderr, "  %s firefox.exe -pid 1234 - Redirect firefox, exclude PID 1234\n\n", argv[0]);
        fprintf(stderr, "SOCKS5 Proxy: %s:%d\n", SOCKS5_PROXY_IP, SOCKS5_PROXY_PORT);
        exit(EXIT_FAILURE);
    }

    strncpy(target_process, argv[1], MAX_PROCESS_NAME - 1);
    target_process[MAX_PROCESS_NAME - 1] = '\0';

    if (argc == 4 && strcmp(argv[2], "-pid") == 0)
    {
        exclude_pid = (DWORD)atoi(argv[3]);
        use_exclude_pid = TRUE;
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
    config->local_proxy_port = LOCAL_PROXY_PORT;

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
        LOCAL_PROXY_PORT, LOCAL_PROXY_PORT);

    message("ProxyBridge started");
    message("Local proxy: localhost:%d", LOCAL_PROXY_PORT);
    message("SOCKS5 proxy: %s:%d", SOCKS5_PROXY_IP, SOCKS5_PROXY_PORT);
    message("Redirecting traffic from: %s", target_process);
    if (use_exclude_pid)
    {
        message("Excluding PID %lu (direct connection)", exclude_pid);
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
            if (use_exclude_pid)
            {
                DWORD conn_pid = get_process_id_from_connection(
                    ip_header->SrcAddr, ntohs(tcp_header->SrcPort));

                if (conn_pid == exclude_pid)
                {
                    // Excluded process - forward unchanged
                    WinDivertSend(handle, packet, packet_len, NULL, &addr);
                    continue;
                }
            }

            // Check if this is traffic FROM local proxy going back to target process
            if (tcp_header->SrcPort == htons(LOCAL_PROXY_PORT))
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
                tcp_header->DstPort = htons(LOCAL_PROXY_PORT);
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
            if (tcp_header->DstPort == htons(LOCAL_PROXY_PORT))
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
    socks5_ip = parse_ipv4(SOCKS5_PROXY_IP);
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
    socks_addr.sin_port = htons(SOCKS5_PROXY_PORT);

    if (connect(socks_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        warning("Failed to connect to SOCKS5 proxy (%d)", WSAGetLastError());
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    // Perform SOCKS5 handshake
    if (socks5_connect(socks_sock, dest_ip, dest_port) != 0)
    {
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
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
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
#define LOCAL_PROXY_PORT 34010
#define LOCAL_UDP_RELAY_PORT 34011
#define MAX_PROCESS_NAME 256

typedef struct PROCESS_RULE {
    UINT32 rule_id;
    char process_name[MAX_PROCESS_NAME];
    char *target_hosts;   // Dynamic: IP filter "*", "192.168.*.*", "10.0.0.1;172.16.0.0"
    char *target_ports;   // Dynamic: Port filter "*", "80", "80;443", "8000-9000"
    RuleProtocol protocol;  // TCP, UDP, or BOTH (for future)
    RuleAction action;
    BOOL enabled;
    struct PROCESS_RULE *next;
} PROCESS_RULE;

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
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

// Track logged connections to avoid dupli
typedef struct LOGGED_CONNECTION {
    DWORD pid;
    UINT32 dest_ip;
    UINT16 dest_port;
    RuleAction action;
    struct LOGGED_CONNECTION *next;
} LOGGED_CONNECTION;

static CONNECTION_INFO *connection_list = NULL;
static LOGGED_CONNECTION *logged_connections = NULL;
static PROCESS_RULE *rules_list = NULL;
static UINT32 g_next_rule_id = 1;
static HANDLE lock = NULL;
static HANDLE windivert_handle = INVALID_HANDLE_VALUE;
static HANDLE packet_thread = NULL;
static HANDLE proxy_thread = NULL;
static HANDLE udp_relay_thread = NULL;
static SOCKET udp_relay_socket = INVALID_SOCKET;
static SOCKET socks5_udp_socket = INVALID_SOCKET;  // TCP control connection
static SOCKET socks5_udp_send_socket = INVALID_SOCKET;  // UDP socket for sending to SOCKS5
static struct sockaddr_in socks5_udp_relay_addr;
static BOOL running = FALSE;
static DWORD g_current_process_id = 0;

static char g_proxy_ip[64] = "";
static UINT16 g_proxy_port = 0;
static UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
static ProxyType g_proxy_type = PROXY_TYPE_SOCKS5;
static char g_proxy_username[256] = "";
static char g_proxy_password[256] = "";
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

// Extract filename from full path  C:\path\chrome.exe  >> chrome.exe
static const char* extract_filename(const char* path)
{
    if (!path) return "";
    const char* last_backslash = strrchr(path, '\\');
    const char* last_slash = strrchr(path, '/');
    const char* last_separator = (last_backslash > last_slash) ? last_backslash : last_slash;

    return last_separator ? (last_separator + 1) : path;
}

static UINT32 parse_ipv4(const char *ip);
static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static int socks5_udp_associate(SOCKET s, struct sockaddr_in *relay_addr);
static DWORD WINAPI udp_relay_server(LPVOID arg);
static BOOL match_ip_pattern(const char *pattern, UINT32 ip);
static BOOL match_port_pattern(const char *pattern, UINT16 port);
static BOOL match_ip_list(const char *ip_list, UINT32 ip);
static BOOL match_port_list(const char *port_list, UINT16 port);
static BOOL match_process_pattern(const char *pattern, const char *process_name);
static BOOL match_process_list(const char *process_list, const char *process_name);
static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static DWORD WINAPI local_proxy_server(LPVOID arg);
static DWORD WINAPI connection_handler(LPVOID arg);
static DWORD WINAPI transfer_handler(LPVOID arg);
static DWORD WINAPI packet_processor(LPVOID arg);
static DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port);
static DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port);
static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);
static RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp);
static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp);
static void add_connection(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port);
static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port);
static BOOL is_connection_tracked(UINT16 src_port);
static void remove_connection(UINT16 src_port);
static BOOL is_connection_already_logged(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action);
static void add_logged_connection(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action);
static void clear_logged_connections(void);


static DWORD WINAPI packet_processor(LPVOID arg)
{
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;

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
            NULL, NULL, &tcp_header, &udp_header, NULL, NULL, NULL, NULL);

        if (ip_header == NULL)
            continue;

        if (udp_header != NULL && tcp_header == NULL)
        {
            if (addr.Outbound)
            {
                if (udp_header->SrcPort == htons(LOCAL_UDP_RELAY_PORT))
                {
                    UINT16 dst_port = ntohs(udp_header->DstPort);
                    UINT32 orig_dest_ip;
                    UINT16 orig_dest_port;

                    if (get_connection(dst_port, &orig_dest_ip, &orig_dest_port))
                    {
                        // Restore both source IP and port to original destination
                        ip_header->SrcAddr = orig_dest_ip;
                        udp_header->SrcPort = htons(orig_dest_port);
                    }                    addr.Outbound = FALSE;
                }
                else if (is_connection_tracked(ntohs(udp_header->SrcPort)))
                {
                    UINT16 src_port = ntohs(udp_header->SrcPort);
                    UINT32 temp_addr = ip_header->DstAddr;
                    udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }
                else
                {
                    UINT16 src_port = ntohs(udp_header->SrcPort);
                    UINT32 src_ip = ip_header->SrcAddr;
                    UINT32 dest_ip = ip_header->DstAddr;
                    UINT16 dest_port = ntohs(udp_header->DstPort);

                    // Always allow DNS (port 53) to go DIRECT for UDP
                    RuleAction action = (dest_port == 53) ? RULE_ACTION_DIRECT : check_process_rule(src_ip, src_port, dest_ip, dest_port, TRUE);

                    if (g_connection_callback != NULL)
                    {
                        char process_name[MAX_PROCESS_NAME];
                        DWORD pid = get_process_id_from_udp_connection(src_ip, src_port);
                        if (pid == 0)
                            pid = get_process_id_from_connection(src_ip, src_port);

                        if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
                        {
                            if (!is_connection_already_logged(pid, dest_ip, dest_port, action))
                            {
                                char dest_ip_str[32];
                                snprintf(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
                                    (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
                                    (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF);

                                char proxy_info[128];
                                if (action == RULE_ACTION_PROXY)
                                {
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy SOCKS5://%s:%d (UDP)",
                                        g_proxy_ip, g_proxy_port);
                                }
                                else if (action == RULE_ACTION_DIRECT)
                                {
                                    snprintf(proxy_info, sizeof(proxy_info), "Direct (UDP)");
                                }
                                else if (action == RULE_ACTION_BLOCK)
                                {
                                    snprintf(proxy_info, sizeof(proxy_info), "Blocked (UDP)");
                                }

                                const char* display_name = extract_filename(process_name);
                                g_connection_callback(display_name, pid, dest_ip_str, dest_port, proxy_info);
                                add_logged_connection(pid, dest_ip, dest_port, action);
                            }
                        }
                    }

                    if (action == RULE_ACTION_BLOCK)
                    {
                        continue;
                    }

                    if (action == RULE_ACTION_PROXY)
                    {
                        add_connection(src_port, src_ip, dest_ip, dest_port);

                        log_message("[UDP REDIRECT] Original: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
                            (src_ip >> 0) & 0xFF, (src_ip >> 8) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 24) & 0xFF, src_port,
                            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF, (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);

                        UINT32 temp_addr = ip_header->DstAddr;
                        udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                        ip_header->DstAddr = ip_header->SrcAddr;
                        ip_header->SrcAddr = temp_addr;
                        addr.Outbound = FALSE;

                        log_message("[UDP REDIRECT] Redirected: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (Outbound=%d)",
                            (ip_header->SrcAddr >> 0) & 0xFF, (ip_header->SrcAddr >> 8) & 0xFF,
                            (ip_header->SrcAddr >> 16) & 0xFF, (ip_header->SrcAddr >> 24) & 0xFF, ntohs(udp_header->SrcPort),
                            (ip_header->DstAddr >> 0) & 0xFF, (ip_header->DstAddr >> 8) & 0xFF,
                            (ip_header->DstAddr >> 16) & 0xFF, (ip_header->DstAddr >> 24) & 0xFF, ntohs(udp_header->DstPort),
                            addr.Outbound);
                    }
                }
            }
            else
            {
                if (udp_header->DstPort != htons(LOCAL_UDP_RELAY_PORT))
                {
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }

                log_message("[UDP INBOUND] Received packet for relay: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
                    (ip_header->SrcAddr >> 0) & 0xFF, (ip_header->SrcAddr >> 8) & 0xFF,
                    (ip_header->SrcAddr >> 16) & 0xFF, (ip_header->SrcAddr >> 24) & 0xFF, ntohs(udp_header->SrcPort),
                    (ip_header->DstAddr >> 0) & 0xFF, (ip_header->DstAddr >> 8) & 0xFF,
                    (ip_header->DstAddr >> 16) & 0xFF, (ip_header->DstAddr >> 24) & 0xFF, ntohs(udp_header->DstPort));
            }

            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
            WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }        // TCP packets only from here
        if (tcp_header == NULL)
            continue;

        if (addr.Outbound)
        {
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
            else
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);
                UINT32 src_ip = ip_header->SrcAddr;
                UINT32 orig_dest_ip = ip_header->DstAddr;
                UINT16 orig_dest_port = ntohs(tcp_header->DstPort);

                RuleAction action = check_process_rule(src_ip, src_port, orig_dest_ip, orig_dest_port, FALSE);

                // Log ALL connections (DIRECT, BLOCK, PROXY) - only ONCE per unique connection
                if (g_connection_callback != NULL)
                {
                    char process_name[MAX_PROCESS_NAME];
                    DWORD pid = get_process_id_from_connection(src_ip, src_port);
                    if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
                    {
                        // Check if we already logged this connection
                        if (!is_connection_already_logged(pid, orig_dest_ip, orig_dest_port, action))
                        {
                            char dest_ip_str[32];
                            snprintf(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
                                (orig_dest_ip >> 0) & 0xFF, (orig_dest_ip >> 8) & 0xFF,
                                (orig_dest_ip >> 16) & 0xFF, (orig_dest_ip >> 24) & 0xFF);

                            char proxy_info[128];
                            if (action == RULE_ACTION_PROXY)
                            {
                                snprintf(proxy_info, sizeof(proxy_info), "Proxy %s://%s:%d",
                                    g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                                    g_proxy_ip, g_proxy_port);
                            }
                            else if (action == RULE_ACTION_DIRECT)
                            {
                                snprintf(proxy_info, sizeof(proxy_info), "Direct");
                            }
                            else if (action == RULE_ACTION_BLOCK)
                            {
                                snprintf(proxy_info, sizeof(proxy_info), "Blocked");
                            }

                            const char* display_name = extract_filename(process_name);
                            g_connection_callback(display_name, pid, dest_ip_str, orig_dest_port, proxy_info);

                            // Mark this connection as logged
                            add_logged_connection(pid, orig_dest_ip, orig_dest_port, action);
                        }
                    }
                }

                if (action == RULE_ACTION_DIRECT)
                {
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }
                else if (action == RULE_ACTION_BLOCK)
                {
                    // Drop the packet - don't send it anywhere
                    continue;
                }
                else if (action == RULE_ACTION_PROXY)
            {
                add_connection(src_port, src_ip, orig_dest_ip, orig_dest_port);

                UINT32 temp_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(g_local_relay_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;
                }
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

// Get process ID for UDP connection
static DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port)
{
    MIB_UDPTABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0;
    DWORD pid = 0;

    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
    {
        return 0;
    }

    udp_table = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (udp_table == NULL)
    {
        return 0;
    }

    if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
    {
        free(udp_table);
        return 0;
    }

    // First pass: Try exact match (IP + port)
    for (DWORD i = 0; i < udp_table->dwNumEntries; i++)
    {
        MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];

        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port)
        {
            pid = row->dwOwningPid;
            break;
        }
    }

    // Second pass: If not found, try matching port on 0.0.0.0 (INADDR_ANY)
    // Many UDP applications bind to 0.0.0.0:port instead of specific IP
    if (pid == 0)
    {
        for (DWORD i = 0; i < udp_table->dwNumEntries; i++)
        {
            MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];

            if (row->dwLocalAddr == 0 &&  // 0.0.0.0 (INADDR_ANY)
                ntohs((UINT16)row->dwLocalPort) == src_port)
            {
                pid = row->dwOwningPid;
                break;
            }
        }
    }

    free(udp_table);
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


        strncpy(name, full_path, name_size - 1);
        name[name_size - 1] = '\0';
        CloseHandle(hProcess);
        return TRUE;
    }

    CloseHandle(hProcess);
    return FALSE;
}

// Match IP pattern against IP address
// Supports: "*" (all), "192.168.1.1" (exact), "192.168.*.*" (wildcard)
static BOOL match_ip_pattern(const char *pattern, UINT32 ip)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // Extract 4 octets from IP (little-endian)
    unsigned char ip_octets[4];
    ip_octets[0] = (ip >> 0) & 0xFF;
    ip_octets[1] = (ip >> 8) & 0xFF;
    ip_octets[2] = (ip >> 16) & 0xFF;
    ip_octets[3] = (ip >> 24) & 0xFF;

    // Parse pattern manually
    char pattern_copy[256];
    strncpy(pattern_copy, pattern, sizeof(pattern_copy) - 1);
    pattern_copy[sizeof(pattern_copy) - 1] = '\0';

    char pattern_octets[4][16];
    int octet_count = 0;
    int char_idx = 0;

    for (int i = 0; i <= (int)strlen(pattern_copy) && octet_count < 4; i++)
    {
        if (pattern_copy[i] == '.' || pattern_copy[i] == '\0')
        {
            pattern_octets[octet_count][char_idx] = '\0';
            octet_count++;
            char_idx = 0;
            if (pattern_copy[i] == '\0')
                break;
        }
        else
        {
            if (char_idx < 15)
                pattern_octets[octet_count][char_idx++] = pattern_copy[i];
        }
    }

    if (octet_count != 4)
        return FALSE;

    for (int i = 0; i < 4; i++)
    {
        if (strcmp(pattern_octets[i], "*") == 0)
            continue;
        int pattern_val = atoi(pattern_octets[i]);
        if (pattern_val != ip_octets[i])
            return FALSE;
    }
    return TRUE;
}

// Match port pattern: "*", "80", "8000-9000"
static BOOL match_port_pattern(const char *pattern, UINT16 port)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    char *dash = strchr(pattern, '-');
    if (dash != NULL)
    {
        int start_port = atoi(pattern);
        int end_port = atoi(dash + 1);
        return (port >= start_port && port <= end_port);
    }

    return (port == atoi(pattern));
}

// Match IP list: "192.168.*.*;10.0.0.1"
static BOOL match_ip_list(const char *ip_list, UINT32 ip)
{
    if (ip_list == NULL || ip_list[0] == '\0' || strcmp(ip_list, "*") == 0)
        return TRUE;

    size_t len = strlen(ip_list) + 1;
    char *list_copy = (char *)malloc(len);
    if (list_copy == NULL)
        return FALSE;

    strncpy(list_copy, ip_list, len);
    BOOL matched = FALSE;
    char *token = strtok(list_copy, ";");
    while (token != NULL)
    {
        while (*token == ' ' || *token == '\t')
            token++;
        if (match_ip_pattern(token, ip))
        {
            matched = TRUE;
            break;
        }
        token = strtok(NULL, ";");
    }
    free(list_copy);
    return matched;
}

// Match port list: "80;443;8000-9000"
static BOOL match_port_list(const char *port_list, UINT16 port)
{
    if (port_list == NULL || port_list[0] == '\0' || strcmp(port_list, "*") == 0)
        return TRUE;

    size_t len = strlen(port_list) + 1;
    char *list_copy = (char *)malloc(len);
    if (list_copy == NULL)
        return FALSE;

    strncpy(list_copy, port_list, len);
    BOOL matched = FALSE;
    char *token = strtok(list_copy, ",;");
    while (token != NULL)
    {
        while (*token == ' ' || *token == '\t')
            token++;
        if (match_port_pattern(token, port))
        {
            matched = TRUE;
            break;
        }
        token = strtok(NULL, ",;");
    }
    free(list_copy);
    return matched;
}

// Match process name with wildcard support
// Supports: "*" (all),
// "chrome.exe" (exact), "fire*.exe" (wildcard), "*.bin" (extension wildcard)
// added support for full paths - C:\Program Files\Google\Chrome\Application\chrome.exe
// Nedd to Test all combination at sanme time
static BOOL match_process_pattern(const char *pattern, const char *process_full_path)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // Extract just the filename from the full path for comparison
    // Windows path sucks
    const char *filename = strrchr(process_full_path, '\\');
    if (filename != NULL)
        filename++; // Skip the backslash
    else
        filename = process_full_path; // No path separator, use as-is

    size_t pattern_len = strlen(pattern);
    size_t name_len = strlen(filename);
    size_t full_path_len = strlen(process_full_path);

    // Check if pattern contains path separators (backslash or forward slash)
    BOOL is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);

    // check if pattern has path seperator match for full path
    const char *match_target = is_full_path_pattern ? process_full_path : filename; // match against filename only
    size_t target_len = is_full_path_pattern ? full_path_len : name_len;

    // check for * at the end: "fire*" or "C:\Program Files\*"
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*')
    {
        // Match prefix: "fire*" matches "firefox.exe"
        return _strnicmp(pattern, match_target, pattern_len - 1) == 0;
    }

    // Check for wildcard at the beginning: "*.exe"
    if (pattern_len > 1 && pattern[0] == '*')
    {
        // Match suffix: "*.exe" matches "chrome.exe"
        const char *pattern_suffix = pattern + 1;
        size_t suffix_len = pattern_len - 1;
        if (target_len >= suffix_len)
        {
            return _stricmp(match_target + target_len - suffix_len, pattern_suffix) == 0;
        }
        return FALSE;
    }

    // check for *  in the middle: "fire*.exe" or C:\Program Files\*\chrome.exe
    const char *star = strchr(pattern, '*');
    if (star != NULL)
    {
        size_t prefix_len = star - pattern;
        const char *suffix = star + 1;
        size_t suffix_len = strlen(suffix);

        // Check prefix matches
        if (_strnicmp(pattern, match_target, prefix_len) != 0)
            return FALSE;

        if (target_len < prefix_len + suffix_len)
            return FALSE;

        return _stricmp(match_target + target_len - suffix_len, suffix) == 0;
    }

    // No * , use case insensitive
    return _stricmp(pattern, match_target) == 0;
}

// Match process list: "chrome.exe;firefox.exe;*.bin"
static BOOL match_process_list(const char *process_list, const char *process_name)
{
    if (process_list == NULL || process_list[0] == '\0' || strcmp(process_list, "*") == 0)
        return TRUE;

    size_t len = strlen(process_list) + 1;
    char *list_copy = (char *)malloc(len);
    if (list_copy == NULL)
        return FALSE;

    strncpy(list_copy, process_list, len);
    BOOL matched = FALSE;

    // Support both semicolon and comma as separators - Need to figure complex rules in CLI parsing
    char *token = strtok(list_copy, ",;");
    while (token != NULL)
    {
        // Skip leading whitespace
        while (*token == ' ' || *token == '\t')
            token++;

        // Remove trailing whitespace   // this shit cause error in CLI parsing
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t'))
        {
            *end = '\0';
            end--;
        }

        // Remove quotes if present: "C:\some app.exe"  - Need to carefully handle this in CLI app
        if (*token == '"' && strlen(token) > 1)
        {
            token++;
            char *quote = strchr(token, '"');
            if (quote != NULL)
                *quote = '\0';
        }

        if (match_process_pattern(token, process_name))
        {
            matched = TRUE;
            break;
        }
        token = strtok(NULL, ",;");
    }
    free(list_copy);
    return matched;
}


// Unified rule matching function for both TCP and UDP
// Matches rules by process name, IP, port, and protocol
static RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp)
{
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *wildcard_rule = NULL;  // Save fully wildcard rule for last

    while (rule != NULL)
    {
        if (!rule->enabled)
        {
            rule = rule->next;
            continue;
        }

        // Check protocol compatibility
        if (rule->protocol == RULE_PROTOCOL_TCP && is_udp)
        {
            rule = rule->next;
            continue;
        }
        if (rule->protocol == RULE_PROTOCOL_UDP && !is_udp)
        {
            rule = rule->next;
            continue;
        }

        // Check if this is a wildcard process rule
        BOOL is_wildcard_process = (strcmp(rule->process_name, "*") == 0 || strcmp(rule->process_name, "ANY") == 0);

        if (is_wildcard_process)
        {
            // Check if wildcard has specific filters
            BOOL has_ip_filter = (strcmp(rule->target_hosts, "*") != 0);
            BOOL has_port_filter = (strcmp(rule->target_ports, "*") != 0);

            if (has_ip_filter || has_port_filter)
            {
                // Filtered wildcard - check if it matches
                if (match_ip_list(rule->target_hosts, dest_ip) &&
                    match_port_list(rule->target_ports, dest_port))
                {
                    // Matched! Return this rule's action
                    return rule->action;
                }
                // Didn't match, continue
                rule = rule->next;
                continue;
            }

            // Fully wildcard rule (no filters) - save for later
            if (wildcard_rule == NULL)
            {
                wildcard_rule = rule;
            }
            rule = rule->next;
            continue;
        }

        // Check if process name matches
        if (match_process_list(rule->process_name, process_name))
        {
            // Process matched! Check IP and port filters
            if (match_ip_list(rule->target_hosts, dest_ip) &&
                match_port_list(rule->target_ports, dest_port))
            {
                // All filters matched! Return this rule's action
                return rule->action;
            }
        }

        rule = rule->next;
    }

    // No specific rule matched, use wildcard if available
    if (wildcard_rule != NULL)
    {
        return wildcard_rule->action;
    }

    // No rule matched at all
    return RULE_ACTION_DIRECT;
}

static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];

    pid = is_udp ? get_process_id_from_udp_connection(src_ip, src_port) : get_process_id_from_connection(src_ip, src_port);
    if (pid == 0 && is_udp)
        pid = get_process_id_from_connection(src_ip, src_port);
    if (pid == 0)
        return RULE_ACTION_DIRECT;

    // Auto-exclude: Always bypass the process that loaded this DLL (prevents loops)
    if (pid == g_current_process_id)
        return RULE_ACTION_DIRECT;

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
        return RULE_ACTION_DIRECT;

    // Use unified rule matching function
    RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp);

    // Additional checks for proxy configuration
    if (action == RULE_ACTION_PROXY && is_udp && g_proxy_type == PROXY_TYPE_HTTP)
    {
        return RULE_ACTION_DIRECT;  // HTTP proxy doesn't support UDP
    }
    if (action == RULE_ACTION_PROXY && (g_proxy_ip[0] == '\0' || g_proxy_port == 0))
    {
        return RULE_ACTION_DIRECT;  // No proxy configured
    }

    return action;
}


static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port)
{
    unsigned char buf[512];
    int len;
    BOOL use_auth = (g_proxy_username[0] != '\0');

    log_message("SOCKS5: Connecting to %d.%d.%d.%d:%d%s",
        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
        use_auth ? " (with auth)" : "");


    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;  // Username/password auth
        if (send(s, (char*)buf, 4, 0) != 4)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }
    else
    {
        buf[1] = 0x01;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }

    len = recv(s, (char*)buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
    {
        log_message("SOCKS5: Invalid auth response");
        return -1;
    }

    // Handle authentication
    if (buf[1] == 0x02)  // Username/password required
    {
        if (!use_auth)
        {
            log_message("SOCKS5: Server requires authentication but no credentials provided");
            return -1;
        }

        // Send username/password (RFC 1929)
        size_t user_len = strlen(g_proxy_username);
        size_t pass_len = strlen(g_proxy_password);
        if (user_len > 255 || pass_len > 255)
        {
            log_message("SOCKS5: Username or password too long");
            return -1;
        }

        buf[0] = 0x01;  // Version of username/password auth
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], g_proxy_username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], g_proxy_password, pass_len);

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len))
        {
            log_message("SOCKS5: Failed to send credentials");
            return -1;
        }

        len = recv(s, (char*)buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
        {
            log_message("SOCKS5: Authentication failed");
            return -1;
        }
        log_message("SOCKS5: Authentication successful");
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        log_message("SOCKS5: Unsupported auth method: 0x%02X", buf[1]);
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



static void base64_encode(const char* input, char* output, size_t output_size)
{
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_len = strlen(input);
    size_t output_len = 0;

    for (size_t i = 0; i < input_len && output_len < output_size - 4; i += 3)
    {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;

        output[output_len++] = base64_chars[b1 >> 2];
        output[output_len++] = base64_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}

static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port)
{
    char request[1024];
    char response[4096];
    int len;
    char *status_line;
    int status_code;
    BOOL use_auth = (g_proxy_username[0] != '\0');

    log_message("HTTP: Connecting to %d.%d.%d.%d:%d%s",
        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
        use_auth ? " (with auth)" : "");

    if (use_auth)
    {
        // Create "username:password" string and encode as Base64
        char credentials[512];
        char encoded[1024];
        snprintf(credentials, sizeof(credentials), "%s:%s", g_proxy_username, g_proxy_password);
        base64_encode(credentials, encoded, sizeof(encoded));

        len = snprintf(request, sizeof(request),
            "CONNECT %d.%d.%d.%d:%d HTTP/1.1\r\n"
            "Host: %d.%d.%d.%d:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
            encoded);
    }
    else
    {
        len = snprintf(request, sizeof(request),
            "CONNECT %d.%d.%d.%d:%d HTTP/1.1\r\n"
            "Host: %d.%d.%d.%d:%d\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port,
            (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
            (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);
    }

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

static int socks5_udp_associate(SOCKET s, struct sockaddr_in *relay_addr)
{
    unsigned char buf[512];
    int len;
    BOOL use_auth = (g_proxy_username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;
        if (send(s, (char*)buf, 4, 0) != 4)
            return -1;
    }
    else
    {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3)
            return -1;
    }

    len = recv(s, (char*)buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
        return -1;

    if (buf[1] == 0x02)
    {
        if (!use_auth)
            return -1;

        size_t user_len = strlen(g_proxy_username);
        size_t pass_len = strlen(g_proxy_password);
        if (user_len > 255 || pass_len > 255)
            return -1;

        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], g_proxy_username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], g_proxy_password, pass_len);

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len))
            return -1;

        len = recv(s, (char*)buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
            return -1;
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        return -1;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;

    if (send(s, (char*)buf, 10, 0) != 10)
        return -1;

    len = recv(s, (char*)buf, 10, 0);
    if (len < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
        return -1;

    relay_addr->sin_family = AF_INET;
    relay_addr->sin_addr.s_addr = *(UINT32*)&buf[4];
    relay_addr->sin_port = *(UINT16*)&buf[8];

    log_message("SOCKS5 UDP relay: %d.%d.%d.%d:%d",
        buf[4], buf[5], buf[6], buf[7], ntohs(relay_addr->sin_port));
    return 0;
}

static DWORD WINAPI udp_relay_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in local_addr, socks_addr, from_addr;
    SOCKET tcp_sock;
    unsigned char recv_buf[MAXBUF];
    unsigned char send_buf[MAXBUF];
    int recv_len, from_len;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return 1;

    udp_relay_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket == INVALID_SOCKET)
    {
        WSACleanup();
        return 1;
    }

    int on = 1;
    setsockopt(udp_relay_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);

    if (bind(udp_relay_socket, (struct sockaddr *)&local_addr, sizeof(local_addr)) == SOCKET_ERROR)
    {
        closesocket(udp_relay_socket);
        udp_relay_socket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET)
    {
        closesocket(udp_relay_socket);
        udp_relay_socket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    UINT32 socks5_ip = parse_ipv4(g_proxy_ip);
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(g_proxy_port);

    if (connect(tcp_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        closesocket(tcp_sock);
        closesocket(udp_relay_socket);
        udp_relay_socket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    if (socks5_udp_associate(tcp_sock, &socks5_udp_relay_addr) != 0)
    {
        closesocket(tcp_sock);
        closesocket(udp_relay_socket);
        udp_relay_socket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    socks5_udp_socket = tcp_sock;

    // Create a separate UDP socket for sending to SOCKS5 proxy
    socks5_udp_send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socks5_udp_send_socket == INVALID_SOCKET)
    {
        closesocket(tcp_sock);
        closesocket(udp_relay_socket);
        udp_relay_socket = INVALID_SOCKET;
        socks5_udp_socket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    log_message("UDP relay listening on port %d", LOCAL_UDP_RELAY_PORT);

    while (running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_relay_socket, &read_fds);
        FD_SET(socks5_udp_send_socket, &read_fds);
        struct timeval timeout = {1, 0};

        int max_fd = (udp_relay_socket > socks5_udp_send_socket) ? udp_relay_socket : socks5_udp_send_socket;
        if (select(max_fd + 1, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        // Check if packet is from local application
        if (FD_ISSET(udp_relay_socket, &read_fds))
        {
            from_len = sizeof(from_addr);
            recv_len = recvfrom(udp_relay_socket, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len > 0)
            {
                UINT32 from_ip = from_addr.sin_addr.s_addr;
                UINT16 from_port = ntohs(from_addr.sin_port);

                log_message("[UDP RELAY] Received %d bytes from local app %d.%d.%d.%d:%d",
                    recv_len,
                    (from_ip >> 0) & 0xFF, (from_ip >> 8) & 0xFF,
                    (from_ip >> 16) & 0xFF, (from_ip >> 24) & 0xFF, from_port);

                // Packet from local application - encapsulate and forward to SOCKS5 proxy
                UINT32 dest_ip;
                UINT16 dest_port;
                if (get_connection(from_port, &dest_ip, &dest_port))
                {
                    log_message("[UDP RELAY] Found connection for port %d -> %d.%d.%d.%d:%d, sending to SOCKS5",
                        from_port,
                        (dest_ip >> 0) & 0xFF, (dest_ip >> 8) & 0xFF,
                        (dest_ip >> 16) & 0xFF, (dest_ip >> 24) & 0xFF, dest_port);

                    send_buf[0] = 0;
                    send_buf[1] = 0;
                    send_buf[2] = 0;
                    send_buf[3] = SOCKS5_ATYP_IPV4;
                    send_buf[4] = (dest_ip >> 0) & 0xFF;
                    send_buf[5] = (dest_ip >> 8) & 0xFF;
                    send_buf[6] = (dest_ip >> 16) & 0xFF;
                    send_buf[7] = (dest_ip >> 24) & 0xFF;
                    send_buf[8] = (dest_port >> 8) & 0xFF;
                    send_buf[9] = (dest_port >> 0) & 0xFF;
                    memcpy(&send_buf[10], recv_buf, recv_len);

                    int sent = sendto(socks5_udp_send_socket, (char*)send_buf, 10 + recv_len, 0,
                          (struct sockaddr *)&socks5_udp_relay_addr, sizeof(socks5_udp_relay_addr));

                    if (sent == SOCKET_ERROR) {
                        int err = WSAGetLastError();
                        log_message("[UDP RELAY ERROR] Failed to send to SOCKS5 proxy: %d", err);
                    }
                }
                else
                {
                    log_message("[UDP RELAY] No connection found for port %d", from_port);
                }
            }
        }

        // Check if packet is from SOCKS5 proxy
        if (FD_ISSET(socks5_udp_send_socket, &read_fds))
        {
            from_len = sizeof(from_addr);
            recv_len = recvfrom(socks5_udp_send_socket, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len > 0)
            {
                // Packet from SOCKS5 proxy - decapsulate and forward to original sender
                if (recv_len < 10)
                    continue;

                // SOCKS5 UDP packet format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) + DATA
                if (recv_buf[2] != 0x00)  // FRAG must be 0
                    continue;

                if (recv_buf[3] != SOCKS5_ATYP_IPV4)  // Only IPv4 supported
                    continue;

                // Extract source IP and port from SOCKS5 header
                UINT32 src_ip = (recv_buf[4] << 0) | (recv_buf[5] << 8) |
                               (recv_buf[6] << 16) | (recv_buf[7] << 24);
                UINT16 src_port = (recv_buf[8] << 8) | recv_buf[9];

                // Find which local port this packet should go to
                WaitForSingleObject(lock, INFINITE);
                CONNECTION_INFO *conn = connection_list;
                struct sockaddr_in target_addr;
                BOOL found = FALSE;
                while (conn != NULL)
                {
                    if (conn->orig_dest_ip == src_ip && conn->orig_dest_port == src_port)
                    {
                        memset(&target_addr, 0, sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_addr.s_addr = conn->src_ip;
                        target_addr.sin_port = htons(conn->src_port);
                        found = TRUE;
                        break;
                    }
                    conn = conn->next;
                }
                ReleaseMutex(lock);

                if (found)
                {
                    memset(&target_addr, 0, sizeof(target_addr));
                    target_addr.sin_family = AF_INET;
                    target_addr.sin_addr.s_addr = conn->src_ip;
                    target_addr.sin_port = htons(conn->src_port);

                    sendto(udp_relay_socket, (char*)&recv_buf[10], recv_len - 10, 0,
                          (struct sockaddr *)&target_addr, sizeof(target_addr));
                }
            }
        }
    }

    closesocket(socks5_udp_socket);
    closesocket(socks5_udp_send_socket);
    closesocket(udp_relay_socket);
    udp_relay_socket = INVALID_SOCKET;
    socks5_udp_socket = INVALID_SOCKET;
    socks5_udp_send_socket = INVALID_SOCKET;
    WSACleanup();
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

PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    if (process_name == NULL || process_name[0] == '\0')
        return 0;

    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (rule == NULL)
        return 0;

    rule->rule_id = g_next_rule_id++;
    strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
    rule->process_name[MAX_PROCESS_NAME - 1] = '\0';
    rule->protocol = protocol;

    if (target_hosts != NULL && target_hosts[0] != '\0')
    {
        size_t len = strlen(target_hosts) + 1;
        rule->target_hosts = (char *)malloc(len);
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
        strncpy(rule->target_hosts, target_hosts, len);
        rule->target_hosts[len - 1] = '\0';
    }
    else
    {
        // Default to "*" ll IPs
        rule->target_hosts = (char *)malloc(2);
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
        strcpy(rule->target_hosts, "*");
    }

    // Dynamically allocate memory for target_ports no size limit!
    if (target_ports != NULL && target_ports[0] != '\0')
    {
        size_t len = strlen(target_ports) + 1;
        rule->target_ports = (char *)malloc(len);
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strncpy(rule->target_ports, target_ports, len);
        rule->target_ports[len - 1] = '\0';
    }
    else
    {
        // Default to "*" - all ports
        rule->target_ports = (char *)malloc(2);
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strcpy(rule->target_ports, "*");
    }

    rule->action = action;
    rule->enabled = TRUE;
    rule->next = rules_list;
    rules_list = rule;

    return rule->rule_id;
}

PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = TRUE;
            return TRUE;
        }
        rule = rule->next;
    }
    return FALSE;
}

PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = FALSE;
            return TRUE;
        }
        rule = rule->next;
    }
    return FALSE;
}

PROXYBRIDGE_API BOOL ProxyBridge_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password)
{
    if (proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return FALSE;

    if (parse_ipv4(proxy_ip) == 0)
        return FALSE;

    strncpy(g_proxy_ip, proxy_ip, sizeof(g_proxy_ip) - 1);
    g_proxy_ip[sizeof(g_proxy_ip) - 1] = '\0';
    g_proxy_port = proxy_port;
    g_proxy_type = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;

    // Store credentials if there
    if (username != NULL && username[0] != '\0')
    {
        strncpy(g_proxy_username, username, sizeof(g_proxy_username) - 1);
        g_proxy_username[sizeof(g_proxy_username) - 1] = '\0';
    }
    else
    {
        g_proxy_username[0] = '\0';
    }

    if (password != NULL && password[0] != '\0')
    {
        strncpy(g_proxy_password, password, sizeof(g_proxy_password) - 1);
        g_proxy_password[sizeof(g_proxy_password) - 1] = '\0';
    }
    else
    {
        g_proxy_password[0] = '\0';
    }

    return TRUE;
}

PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback)
{
    g_log_callback = callback;
}

PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback)
{
    g_connection_callback = callback;
}

// Check if connection already logged (deduplication)
static BOOL is_connection_already_logged(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action)
{
    BOOL found = FALSE;
    WaitForSingleObject(lock, INFINITE);

    LOGGED_CONNECTION *logged = logged_connections;
    while (logged != NULL)
    {
        if (logged->pid == pid &&
            logged->dest_ip == dest_ip &&
            logged->dest_port == dest_port &&
            logged->action == action)
        {
            found = TRUE;
            break;
        }
        logged = logged->next;
    }

    ReleaseMutex(lock);
    return found;
}

// Add connection to logged list
static void add_logged_connection(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action)
{
    WaitForSingleObject(lock, INFINITE);

    LOGGED_CONNECTION *logged = (LOGGED_CONNECTION *)malloc(sizeof(LOGGED_CONNECTION));
    if (logged != NULL)
    {
        logged->pid = pid;
        logged->dest_ip = dest_ip;
        logged->dest_port = dest_port;
        logged->action = action;
        logged->next = logged_connections;
        logged_connections = logged;
    }

    ReleaseMutex(lock);
}

// Clear all logged connections
static void clear_logged_connections(void)
{
    WaitForSingleObject(lock, INFINITE);

    while (logged_connections != NULL)
    {
        LOGGED_CONNECTION *to_free = logged_connections;
        logged_connections = logged_connections->next;
        free(to_free);
    }

    ReleaseMutex(lock);
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

    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        udp_relay_thread = CreateThread(NULL, 1, udp_relay_server, NULL, 0, NULL);
        if (udp_relay_thread == NULL)
        {
            running = FALSE;
            WaitForSingleObject(proxy_thread, INFINITE);
            CloseHandle(proxy_thread);
            proxy_thread = NULL;
            return FALSE;
        }
    }

    Sleep(500);

    snprintf(filter, sizeof(filter),
        "(tcp and (outbound or (tcp.DstPort == %d or tcp.SrcPort == %d))) or (udp and (outbound or (udp.DstPort == %d or udp.SrcPort == %d)))",
        g_local_relay_port, g_local_relay_port, LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT);

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

    int rule_count = 0;
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        const char *action_str = (rule->action == RULE_ACTION_PROXY) ? "PROXY" :
                                 (rule->action == RULE_ACTION_BLOCK) ? "BLOCK" : "DIRECT";
        log_message("Rule: %s -> %s", rule->process_name, action_str);
        rule_count++;
        rule = rule->next;
    }
    if (rule_count == 0)
        log_message("No rules configured - all traffic will be direct");

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

    if (udp_relay_thread != NULL)
    {
        WaitForSingleObject(udp_relay_thread, 5000);
        CloseHandle(udp_relay_thread);
        udp_relay_thread = NULL;
    }

    WaitForSingleObject(lock, INFINITE);
    while (connection_list != NULL)
    {
        CONNECTION_INFO *to_free = connection_list;
        connection_list = connection_list->next;
        free(to_free);
    }
    ReleaseMutex(lock);

    // Clear logged connections list
    clear_logged_connections();

    log_message("ProxyBridge stopped");

    return TRUE;
}


PROXYBRIDGE_API int ProxyBridge_TestConnection(const char* target_host, UINT16 target_port, char* result_buffer, size_t buffer_size)
{
    WSADATA wsa;
    SOCKET test_sock = INVALID_SOCKET;
    struct sockaddr_in proxy_addr;
    struct hostent* host_info;
    UINT32 target_ip;
    int ret = -1;
    char temp_buffer[512];

    if (g_proxy_ip[0] == '\0' || g_proxy_port == 0)
    {
        snprintf(result_buffer, buffer_size, "ERROR: No proxy configured");
        return -1;
    }

    if (target_host == NULL || target_host[0] == '\0')
    {
        snprintf(result_buffer, buffer_size, "ERROR: Invalid target host");
        return -1;
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        snprintf(result_buffer, buffer_size, "ERROR: WSAStartup failed (%d)", WSAGetLastError());
        return -1;
    }

    snprintf(temp_buffer, sizeof(temp_buffer), "Testing connection to %s:%d via %s proxy %s:%d...\n",
        target_host, target_port,
        g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
        g_proxy_ip, g_proxy_port);
    strncpy(result_buffer, temp_buffer, buffer_size - 1);


    host_info = gethostbyname(target_host);
    if (host_info == NULL)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to resolve hostname %s (%d)\n", target_host, WSAGetLastError());
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        WSACleanup();
        return -1;
    }
    target_ip = *(UINT32*)host_info->h_addr_list[0];

    snprintf(temp_buffer, sizeof(temp_buffer), "Resolved %s to %d.%d.%d.%d\n",
        target_host,
        (target_ip >> 0) & 0xFF, (target_ip >> 8) & 0xFF,
        (target_ip >> 16) & 0xFF, (target_ip >> 24) & 0xFF);
    strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);

    // Create socket
    test_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (test_sock == INVALID_SOCKET)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Socket creation failed (%d)\n", WSAGetLastError());
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        WSACleanup();
        return -1;
    }

    DWORD timeout = 10000;
    setsockopt(test_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(test_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = parse_ipv4(g_proxy_ip);
    proxy_addr.sin_port = htons(g_proxy_port);

    snprintf(temp_buffer, sizeof(temp_buffer), "Connecting to proxy %s:%d...\n", g_proxy_ip, g_proxy_port);
    strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);

    if (connect(test_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to connect to proxy (%d)\n", WSAGetLastError());
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        closesocket(test_sock);
        WSACleanup();
        return -1;
    }

    strncat(result_buffer, "Connected to proxy server\n", buffer_size - strlen(result_buffer) - 1);

    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        if (socks5_connect(test_sock, target_ip, target_port) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: SOCKS5 handshake failed\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            closesocket(test_sock);
            WSACleanup();
            return -1;
        }
        strncat(result_buffer, "SOCKS5 handshake successful\n", buffer_size - strlen(result_buffer) - 1);
    }
    else
    {
        if (http_connect(test_sock, target_ip, target_port) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: HTTP CONNECT failed\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            closesocket(test_sock);
            WSACleanup();
            return -1;
        }
        strncat(result_buffer, "HTTP CONNECT successful\n", buffer_size - strlen(result_buffer) - 1);
    }


    char http_request[512];
    snprintf(http_request, sizeof(http_request),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: ProxyBridge/1.0\r\n"
        "\r\n", target_host);

    if (send(test_sock, http_request, strlen(http_request), 0) == SOCKET_ERROR)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to send test request (%d)\n", WSAGetLastError());
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        closesocket(test_sock);
        WSACleanup();
        return -1;
    }

    strncat(result_buffer, "Sent HTTP GET request\n", buffer_size - strlen(result_buffer) - 1);
    char response[1024];
    int bytes_received = recv(test_sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0';

        if (strstr(response, "HTTP/") != NULL)
        {
            char* status_line = strstr(response, "HTTP/");
            int status_code = 0;
            if (status_line != NULL)
            {
                sscanf(status_line, "HTTP/%*s %d", &status_code);
            }

            snprintf(temp_buffer, sizeof(temp_buffer), "SUCCESS: Received HTTP %d response (%d bytes)\n", status_code, bytes_received);
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            ret = 0; // Success
        }
        else
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Received data but not valid HTTP response\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            ret = -1; // Failure - not a valid HTTP response
        }
    }
    else if (bytes_received == 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Connection closed by remote host (no data received)\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        ret = -1; // Failure
    }
    else
    {
        int error_code = WSAGetLastError();
        if (error_code == WSAETIMEDOUT)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Connection timeout - no response received\n");
        }
        else
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to receive response (%d)\n", error_code);
        }
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        ret = -1; // Failure
    }

    closesocket(test_sock);
    WSACleanup();

    if (ret == 0)
    {
        strncat(result_buffer, "\n✓ Proxy connection test PASSED\n", buffer_size - strlen(result_buffer) - 1);
    }
    else
    {
        strncat(result_buffer, "\n✗ Proxy connection test FAILED\n", buffer_size - strlen(result_buffer) - 1);
    }

    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // Store the PID of the process that loaded this DLL
            g_current_process_id = GetCurrentProcessId();
            break;
        case DLL_PROCESS_DETACH:
            if (running)
                ProxyBridge_Stop();
            if (lock != NULL)
            {
                CloseHandle(lock);
                lock = NULL;
            }
            while (rules_list != NULL)
            {
                PROCESS_RULE *to_free = rules_list;
                rules_list = rules_list->next;

                if (to_free->target_hosts != NULL)
                    free(to_free->target_hosts);
                if (to_free->target_ports != NULL)
                    free(to_free->target_ports);

                free(to_free);
            }
            break;
    }
    return TRUE;
}
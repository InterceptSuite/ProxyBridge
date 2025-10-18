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
static PROCESS_RULE *rules_list = NULL;
static UINT32 g_next_rule_id = 1;
static HANDLE lock = NULL;
static HANDLE windivert_handle = INVALID_HANDLE_VALUE;
static HANDLE packet_thread = NULL;
static HANDLE proxy_thread = NULL;
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
static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);
static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port);
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
                RuleAction action = check_process_rule(ip_header->SrcAddr, ntohs(tcp_header->SrcPort),
                                                                       ip_header->DstAddr, ntohs(tcp_header->DstPort));

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

                        char proxy_info[128];
                        snprintf(proxy_info, sizeof(proxy_info), "Redirect Proxy %s://%s:%d",
                            g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                            g_proxy_ip, g_proxy_port);

                        const char* display_name = extract_filename(process_name);
                        g_connection_callback(display_name, pid, dest_ip_str, orig_dest_port, proxy_info);
                    }
                }

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


static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];
    RuleAction wildcard_action = RULE_ACTION_DIRECT;
    BOOL wildcard_found = FALSE;

    pid = get_process_id_from_connection(src_ip, src_port);
    if (pid == 0)
        return RULE_ACTION_DIRECT;

    // Auto-exclude: Always bypass the process that loaded this DLL (prevents loops)
    //// DOO NOT Remove THIS - If * rule is used, not checking our own process will cause loop
    if (pid == g_current_process_id)
        return RULE_ACTION_DIRECT;

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
        return RULE_ACTION_DIRECT;

    // First pass: Check specific process rules and save wildcard
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (!rule->enabled)
        {
            rule = rule->next;
            continue;
        }

        // If this is a wildcard rule, save it for later but don't process it yet
        if (strcmp(rule->process_name, "*") == 0 || strcmp(rule->process_name, "ANY") == 0)
        {
            wildcard_action = rule->action;
            wildcard_found = TRUE;
            rule = rule->next;
            continue;  // Skip to next rule
        }

        // Use new wildcard process matching
        // Supports: "chrome.exe", "fire*.exe", "*.bin", "chrome.exe;firefox.exe;*.bin"
        if (match_process_list(rule->process_name, process_name))
        {
            // Process name matched! Now check IP and port filters
            if (!match_ip_list(rule->target_hosts, dest_ip))
            {
                rule = rule->next;
                continue;  // IP doesn't match, try next rule
            }

            if (!match_port_list(rule->target_ports, dest_port))
            {
                rule = rule->next;
                continue;  // Port doesn't match, try next rule
            }

            // WIP - protocol based check
            // Process name, IP, and port ALL matched!
            RuleAction action = rule->action;
            if (action == RULE_ACTION_PROXY && (g_proxy_ip[0] == '\0' || g_proxy_port == 0))
            {
                return RULE_ACTION_DIRECT;
            }
            return action;
        }
        rule = rule->next;
    }

    // Second pass: No specific match found, use wildcard if it exists
    if (wildcard_found)
    {
        if (wildcard_action == RULE_ACTION_PROXY && (g_proxy_ip[0] == '\0' || g_proxy_port == 0))
        {
            return RULE_ACTION_DIRECT;
        }
        return wildcard_action;
    }

    // No match at all - default to DIRECT
    return RULE_ACTION_DIRECT;
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
#include "pb_internal.h"

// Core: shared globals, WinDivert packet loop, lifecycle (Start/Stop), DllMain.

// ==== shared global definitions ====
PROXY_CONFIG g_proxy_configs[MAX_PROXY_CONFIGS];
int g_proxy_config_count = 0;
UINT32 g_next_config_id = 1;

CONNECTION_INFO *connection_hash_table[CONNECTION_HASH_SIZE] = {NULL};
// Reverse index keyed by original destination, so inbound UDP relay replies map back to
// the client in O(1) instead of scanning the whole table per datagram (games/downloads
// generate a high inbound packet rate against a large connection table). Both tables are
// guarded by `lock`; every add/update/remove/cleanup keeps them consistent.
CONNECTION_INFO *connection_rev_table[CONNECTION_HASH_SIZE] = {NULL};
LOGGED_CONNECTION *logged_connections = NULL;
int g_logged_count = 0;  // running length of logged_connections (guarded by `lock`)
PROCESS_RULE *rules_list = NULL;
UINT32 g_next_rule_id = 1;
SRWLOCK lock;

// Guards rules_list and the rule nodes/strings it points to. Separate from `lock`
// (which guards the connection table + PID cache) so rule edits from the GUI thread
// never block the packet path's connection bookkeeping. A zero-initialised SRWLOCK is
// already in the valid unlocked state, so this is safe to use before ProxyBridge_Start.
SRWLOCK g_rules_lock;
HANDLE windivert_handle = INVALID_HANDLE_VALUE;
HANDLE packet_thread[NUM_PACKET_THREADS] = {NULL};
HANDLE proxy_thread = NULL;
HANDLE udp_relay_thread = NULL;
HANDLE cleanup_thread = NULL;
PID_CACHE_ENTRY *pid_cache[PID_CACHE_SIZE] = {NULL};
volatile BOOL g_has_active_rules = FALSE;
// Set when at least one enabled rule carries a domain filter. Gates the DNS-cache
// lookup in match_rule so setups without domain rules pay zero extra cost.
volatile BOOL g_has_domain_rules = FALSE;
SOCKET udp_relay_socket = INVALID_SOCKET;
SOCKET udp_relay_socket6 = INVALID_SOCKET;
volatile BOOL running = FALSE;
DWORD g_current_process_id = 0;

BOOL g_traffic_logging_enabled = TRUE;

DNS_CACHE_ENTRY    *g_dns_cache[DNS_CACHE_BUCKETS];
DNS_CACHE_ENTRY_V6 *g_dns_cache_v6[DNS_CACHE_BUCKETS];
SRWLOCK             g_dns_cache_lock;

// per src port decision cache.
//
// check_process_rule() resolves (src_port) to DIRECT, PROXY, or BLOCK,
// every subsequent packet from that port gets the cached answer in 5 cycles
// (one atomic read). this is needed else every outbound data/ack segment from an
// established connection re runs the full check_process_rule() path:
//   GetExtendedTcpTable (malloc + kernel roundtrip)
//   + OpenProcess + QueryFullProcessImageName
//   + rule list walk
// On a sustained 300 Mbps download (17 000 packets/sec) that is thousands of
// kernel calls per second, saturating a single core.
//
// Layout: two 2048-LONG bitmaps, 8 KB each.
//   port_decided_bitmap : bit set = decision is cached for this port
//   port_direct_bitmap  : bit set = decision was DIRECT (bit clear = PROXY/BLOCK)
// Together they encode three states per port:
//   decided=0            -> no cached decision, call check_process_rule
//   decided=1, direct=1  -> DIRECT, pass packet unchanged
//   decided=1, direct=0  -> already added to connection (PROXY/BLOCK handled)
//
// Thread safety: InterlockedOr/And for writes; plain aligned 32-bit read for
// reads (x86/x64 aligned read is atomic; we only need visibility, not ordering).
volatile LONG port_decided_bitmap[2048] = {0};  // 8 KB
volatile LONG port_direct_bitmap[2048]  = {0};  // 8 KB

UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
BOOL g_localhost_via_proxy = FALSE;  // default disabled for security - most proxy server block localhost for ssrf and also many app might not work if localhost trafic goes to remote server if proxy server is on diffrent machine
LogCallback g_log_callback = NULL;
ConnectionCallback g_connection_callback = NULL;

char  *g_pidtbl_buf = NULL;
DWORD  g_pidtbl_cap = 0;

DWORD WINAPI packet_processor(LPVOID arg)
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

        PWINDIVERT_IPV6HDR ipv6_header = NULL;
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, NULL,
            NULL, NULL, &tcp_header, &udp_header, NULL, NULL, NULL, NULL);

        if (ip_header == NULL)
        {
            if (ipv6_header == NULL) { continue; }

            // IPv6 UDP
            if (tcp_header == NULL && udp_header != NULL)
            {
                if (addr.Outbound)
                {
                    UINT16 sp = ntohs(udp_header->SrcPort);
                    UINT16 dp = ntohs(udp_header->DstPort);

                    // relay response: restore orig src port/addr
                    if (sp == LOCAL_UDP_RELAY_PORT)
                    {
                        UINT16 client_sp = ntohs(udp_header->DstPort);
                        UINT8  orig_dst6[16]; UINT16 orig_dp = 0; UINT32 dummy = 0;
                        if (get_connection_full_v6(client_sp, TRUE, orig_dst6, &orig_dp, &dummy))
                        {
                            memcpy(ipv6_header->SrcAddr, orig_dst6, 16);
                            udp_header->SrcPort = htons(orig_dp);
                        }
                        // ::1 loopback: keep OUTBOUND so the loopback adapter echo
                        // delivers reliably (same reasoning as IPv4 path below).
                        // Non-loopback: inject INBOUND.
                        static const UINT8 _lb6r[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                        if (memcmp(ipv6_header->DstAddr, _lb6r, 16) != 0)
                            addr.Outbound = FALSE;
                        goto ipv6u_send;
                    }

                    if (is_connection_tracked(sp, TRUE))
                    {
                        udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                        static const UINT8 _lb6u2[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                        BOOL both_lb=(memcmp(ipv6_header->SrcAddr,_lb6u2,16)==0&&memcmp(ipv6_header->DstAddr,_lb6u2,16)==0);
                        if (!both_lb)
                        {
                            UINT32 tmp[4];
                            memcpy(tmp,ipv6_header->DstAddr,16);
                            memcpy(ipv6_header->DstAddr,ipv6_header->SrcAddr,16);
                            memcpy(ipv6_header->SrcAddr,tmp,16);
                            addr.Outbound = FALSE;
                        }
                        goto ipv6u_send;
                    }

                    if (is_ipv6_multicast_or_linklocal((const UINT8*)ipv6_header->DstAddr))
                    {
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }

                    if (!g_has_active_rules && g_connection_callback == NULL)
                    {
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }

                    RuleAction action6u;
                    DWORD pid6u = 0;
                    UINT32 pcid6u = 0;
                    action6u = check_process_rule_v6((const UINT8*)ipv6_header->SrcAddr, sp, (const UINT8*)ipv6_header->DstAddr, dp, TRUE, &pid6u, &pcid6u);

                    if (action6u == RULE_ACTION_PROXY && !g_localhost_via_proxy)
                    {
                        const UINT8 *d6=(const UINT8*)ipv6_header->DstAddr;
                        static const UINT8 lb6[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                        static const UINT8 v4p[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
                        if (memcmp(d6,lb6,16)==0||(memcmp(d6,v4p,12)==0&&d6[12]==127))
                            action6u = RULE_ACTION_DIRECT;
                    }

                    // Override PROXY to DIRECT for DHCPv6 ports (546=client, 547=server)
                    if (action6u == RULE_ACTION_PROXY && (dp == 546 || dp == 547))
                        action6u = RULE_ACTION_DIRECT;

                    if (g_connection_callback != NULL && pid6u > 0)
                    {
                        // Fold the 128-bit destination into a 32-bit key so the log-dedup
                        // table distinguishes different IPv6 hosts. Passing 0 (as before)
                        // collapsed every IPv6 destination on the same port/action into one
                        // key, causing distinct hosts to be dropped as duplicates.
                        const UINT32 *dw6 = (const UINT32 *)ipv6_header->DstAddr;
                        UINT32 v6key = dw6[0] ^ dw6[1] ^ dw6[2] ^ dw6[3];

                        char pname[MAX_PROCESS_NAME];
                        if (get_process_name_from_pid(pid6u, pname, sizeof(pname)))
                        {
                            if (!is_connection_already_logged(pid6u, v6key, dp, action6u))
                            {
                                char dstr[64];
                                inet_ntop(AF_INET6, ipv6_header->DstAddr, dstr, sizeof(dstr));
                                char pinfo[128];
                                if (action6u==RULE_ACTION_PROXY){PROXY_CONFIG*pc=find_proxy_config(pcid6u);if(pc)snprintf(pinfo,sizeof(pinfo),"Proxy %s://%s:%d (UDP)",pc->type==PROXY_TYPE_HTTP?"HTTP":"SOCKS5",pc->host,pc->port);else snprintf(pinfo,sizeof(pinfo),"Proxy (UDP)");}
                                else if(action6u==RULE_ACTION_DIRECT) snprintf(pinfo,sizeof(pinfo),"Direct (UDP)");
                                else snprintf(pinfo,sizeof(pinfo),"Blocked (UDP)");
                                g_connection_callback(extract_filename(pname),pid6u,dstr,dp,pinfo);
                                if(g_traffic_logging_enabled) add_logged_connection(pid6u,v6key,dp,action6u);
                            }
                        }
                    }

                    if (action6u == RULE_ACTION_BLOCK) continue;

                    if (action6u == RULE_ACTION_PROXY)
                    {
                        PROXY_CONFIG *pc6u = find_proxy_config(pcid6u);
                        if (pc6u == NULL || pc6u->type != PROXY_TYPE_SOCKS5)
                        {
                            // HTTP proxy can't relay UDP - drop
                            continue;
                        }
                        add_connection_v6(sp, TRUE, (const UINT8*)ipv6_header->SrcAddr, (const UINT8*)ipv6_header->DstAddr, dp, pcid6u);

                        udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                        static const UINT8 _lb6up[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                        BOOL both_lb=(memcmp(ipv6_header->SrcAddr,_lb6up,16)==0&&memcmp(ipv6_header->DstAddr,_lb6up,16)==0);
                        if (both_lb)
                        {
                            memset(ipv6_header->DstAddr, 0, 16);
                            ((UINT8*)ipv6_header->DstAddr)[15] = 1;
                        }
                        else
                        {
                            UINT32 tmp[4];
                            memcpy(tmp, ipv6_header->DstAddr, 16);
                            memcpy(ipv6_header->DstAddr, ipv6_header->SrcAddr, 16);
                            memcpy(ipv6_header->SrcAddr, tmp, 16);
                            addr.Outbound = FALSE;
                        }
                        goto ipv6u_send;
                    }
                    else
                    {
                        // DIRECT (or no matching rule): unmodified packet, send as-is without
                        // recomputing checksums (wasteful + can clash with NIC offload, #161).
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }
                }
                else
                {
                    if (udp_header->DstPort != htons(LOCAL_UDP_RELAY_PORT))
                    {
                        // Snoop IPv6 DNS responses (AAAA records) for the domain cache.
                        if (ntohs(udp_header->SrcPort) == 53)
                        {
                            const UINT8 *udp_payload6 = (const UINT8 *)udp_header + sizeof(WINDIVERT_UDPHDR);
                            int udp_payload6_len = (int)(ntohs(udp_header->Length) - sizeof(WINDIVERT_UDPHDR));
                            if (udp_payload6_len > 0)
                                snoop_dns_response(udp_payload6, udp_payload6_len);
                        }
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }
                }

            ipv6u_send:
                WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
                WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }

            // IPv6 TCP only below
            if (tcp_header == NULL)
            {
                WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }

            if (addr.Outbound)
            {
                UINT16 sp = ntohs(tcp_header->SrcPort);
                UINT16 dp = ntohs(tcp_header->DstPort);

                if (port_is_decided(sp))
                {
                    if (tcp_header->Fin || tcp_header->Rst) port_clear(sp);
                    if (port_is_direct(sp))
                    {
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }
                }

                // relay response: restore original src port and fix up addresses
                if (sp == (UINT16)g_local_relay_port)
                {
                    UINT16 client_sp = ntohs(tcp_header->DstPort);
                    UINT8  orig_dst6[16];
                    UINT16 orig_dst_port = 0;
                    UINT32 dummy_cfg = 0;
                    get_connection_full_v6(client_sp, FALSE, orig_dst6, &orig_dst_port, &dummy_cfg);
                    if (orig_dst_port) tcp_header->SrcPort = htons(orig_dst_port);

                    static const UINT8 _lb6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                    BOOL both_lb = (memcmp(ipv6_header->SrcAddr, _lb6, 16) == 0 &&
                                    memcmp(ipv6_header->DstAddr, _lb6, 16) == 0);
                    if (!both_lb)
                    {
                        UINT32 tmp[4];
                        memcpy(tmp, ipv6_header->DstAddr, 16);
                        memcpy(ipv6_header->DstAddr, ipv6_header->SrcAddr, 16);
                        memcpy(ipv6_header->SrcAddr, tmp, 16);
                        addr.Outbound = FALSE;
                    }
                    if (tcp_header->Fin || tcp_header->Rst) remove_connection(client_sp, FALSE);
                    goto ipv6_send;
                }

                if (is_connection_tracked(sp, FALSE))
                {
                    if (tcp_header->Fin || tcp_header->Rst) { remove_connection(sp, FALSE); port_clear(sp); }
                    tcp_header->DstPort = htons(g_local_relay_port);

                    static const UINT8 _lb6t[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                    BOOL both_lb = (memcmp(ipv6_header->SrcAddr, _lb6t, 16) == 0 &&
                                    memcmp(ipv6_header->DstAddr, _lb6t, 16) == 0);
                    if (!both_lb)
                    {
                        UINT32 tmp[4];
                        memcpy(tmp, ipv6_header->DstAddr, 16);
                        memcpy(ipv6_header->DstAddr, ipv6_header->SrcAddr, 16);
                        memcpy(ipv6_header->SrcAddr, tmp, 16);
                        addr.Outbound = FALSE;
                    }
                    goto ipv6_send;
                }

                // skip multicast/link-local
                if (is_ipv6_multicast_or_linklocal((const UINT8*)ipv6_header->DstAddr))
                {
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }

                if (!g_has_active_rules && g_connection_callback == NULL)
                {
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }

                RuleAction action6;
                DWORD pid6 = 0;
                UINT32 proxy_config_id6 = 0;
                action6 = check_process_rule_v6((const UINT8*)ipv6_header->SrcAddr, sp, (const UINT8*)ipv6_header->DstAddr, dp, FALSE, &pid6, &proxy_config_id6);

                // ::1 IPv6 loopback - use  same "Localhost via Proxy" toggle as IPv4 127.
                if (action6 == RULE_ACTION_PROXY && !g_localhost_via_proxy)
                {
                    const UINT8 *dst6 = (const UINT8*)ipv6_header->DstAddr;
                    // check for ::1 (loopback) or ::ffff:127.x.x.x (v4-mapped loopback)
                    static const UINT8 loopback6[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
                    static const UINT8 v4mapped_pfx[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
                    BOOL is_lb6 = (memcmp(dst6, loopback6, 16) == 0);
                    BOOL is_v4mapped_lb = (!is_lb6 && memcmp(dst6, v4mapped_pfx, 12) == 0 && dst6[12] == 127);
                    if (is_lb6 || is_v4mapped_lb)
                        action6 = RULE_ACTION_DIRECT;
                }

                if (g_connection_callback != NULL && tcp_header->Syn && !tcp_header->Ack && pid6 > 0)
                {
                    // Fold the 128-bit destination into a 32-bit dedup key so different
                    // IPv6 hosts aren't collapsed into one entry (see IPv6 UDP path).
                    const UINT32 *dw6 = (const UINT32 *)ipv6_header->DstAddr;
                    UINT32 v6key = dw6[0] ^ dw6[1] ^ dw6[2] ^ dw6[3];

                    char process_name[MAX_PROCESS_NAME];
                    if (get_process_name_from_pid(pid6, process_name, sizeof(process_name)))
                    {
                        if (!is_connection_already_logged(pid6, v6key, dp, action6))
                        {
                            char dest_ip_str[64];
                            const UINT8 *d6 = (const UINT8*)ipv6_header->DstAddr;
                            inet_ntop(AF_INET6, d6, dest_ip_str, sizeof(dest_ip_str));

                            char proxy_info[128];
                            if (action6 == RULE_ACTION_PROXY)
                            {
                                PROXY_CONFIG *pcfg = find_proxy_config(proxy_config_id6);
                                if (pcfg != NULL)
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy %s://%s:%d",
                                        pcfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                                        pcfg->host, pcfg->port);
                                else
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy");
                            }
                            else if (action6 == RULE_ACTION_DIRECT)
                                snprintf(proxy_info, sizeof(proxy_info), "Direct");
                            else
                                snprintf(proxy_info, sizeof(proxy_info), "Blocked");

                            const char *display_name = extract_filename(process_name);
                            g_connection_callback(display_name, pid6, dest_ip_str, dp, proxy_info);

                            if (g_traffic_logging_enabled)
                                add_logged_connection(pid6, v6key, dp, action6);
                        }
                    }
                }

                if (action6 == RULE_ACTION_DIRECT)
                {
                    port_set_direct(sp);
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }
                else if (action6 == RULE_ACTION_BLOCK)
                {
                    port_set_decided(sp);
                    continue;
                }
                else if (action6 == RULE_ACTION_PROXY)
                {
                    add_connection_v6(sp, FALSE, (const UINT8*)ipv6_header->SrcAddr, (const UINT8*)ipv6_header->DstAddr, dp, proxy_config_id6);
                    port_set_decided(sp);
                    tcp_header->DstPort = htons(g_local_relay_port);

                    static const UINT8 _lb6p[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                    BOOL both_lb = (memcmp(ipv6_header->SrcAddr, _lb6p, 16) == 0 &&
                                    memcmp(ipv6_header->DstAddr, _lb6p, 16) == 0);
                    if (!both_lb)
                    {
                        UINT32 tmp[4];
                        memcpy(tmp, ipv6_header->DstAddr, 16);
                        memcpy(ipv6_header->DstAddr, ipv6_header->SrcAddr, 16);
                        memcpy(ipv6_header->SrcAddr, tmp, 16);
                        addr.Outbound = FALSE;
                    }
                    // loopback (::1→::1): just changed DstPort, keep Outbound=TRUE
                    goto ipv6_send;
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

        ipv6_send:
            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
            WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }

        if (udp_header != NULL && tcp_header == NULL)
        {
            if (addr.Outbound)
            {
                if (udp_header->SrcPort == htons(LOCAL_UDP_RELAY_PORT))
                {
                    UINT16 dst_port = ntohs(udp_header->DstPort);
                    UINT32 orig_dest_ip;
                    UINT16 orig_dest_port;

                    if (get_connection(dst_port, TRUE, &orig_dest_ip, &orig_dest_port))
                    {
                        // Restore both source IP and port to original destination
                        ip_header->SrcAddr = orig_dest_ip;
                        udp_header->SrcPort = htons(orig_dest_port);

                        // loopback need outbound injection inbound dont work on windows loopback
                        // bcz fast path skip the recive layer we inject into
                        // outbound makes loopback echo it back as inbound which actualy reach socket
                        // impostor flag stops it getting recaptured again
                        // for real nic inbound injection works fine no extra hop
                        BYTE dst_first_octet = (ntohl(ip_header->DstAddr) >> 24) & 0xFF;
                        if (dst_first_octet != 127)
                            addr.Outbound = FALSE;
                        // else: stay OUTBOUND - loopback echo delivers the packet
                    }
                    else
                    {
                        /* Connection entry gone expired or not added
                         * relay port 34011 as source would be rejected by any connected
                         * socket expecting the real server port.  Drop instead. */
                        log_message("[UDP RELAY] No tracked connection for relay response to port %d dropping", dst_port);
                        continue;
                    }
                }
                else if (is_connection_tracked(ntohs(udp_header->SrcPort), TRUE))
                {
                    UINT16 src_port = ntohs(udp_header->SrcPort);
                    udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);

                    BYTE src_first_octet = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                    BOOL src_is_loopback = (src_first_octet == 127);
                    if (src_is_loopback)
                    {
                        ip_header->DstAddr = htonl(INADDR_LOOPBACK);
                    }
                    else
                    {
                        UINT32 temp_addr = ip_header->DstAddr;
                        ip_header->DstAddr = ip_header->SrcAddr;
                        ip_header->SrcAddr = temp_addr;
                        addr.Outbound = FALSE;
                    }
                }
                else
                {
                    UINT16 src_port = ntohs(udp_header->SrcPort);
                    UINT32 src_ip = ip_header->SrcAddr;
                    UINT32 dest_ip = ip_header->DstAddr;
                    UINT16 dest_port = ntohs(udp_header->DstPort);

                    // if no rule configuree all connection direct with no checks avoid unwanted memory and pocessing whcich could delay
                    if (!g_has_active_rules && g_connection_callback == NULL)
                    {
                        // No rules and no logging - pass through immediately (no checksum needed for unmodified packets)
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }

                    RuleAction action;
                    DWORD pid = 0;
                    UINT32 proxy_config_id = 0;

                    action = check_process_rule(src_ip, src_port, dest_ip, dest_port, TRUE, &pid, &proxy_config_id);

                    // override PROXY to DIRECT if localhost proxy is disabled and destination is localhost
                    BYTE dest_first_octet = (dest_ip >> 0) & 0xFF;
                    if (action == RULE_ACTION_PROXY && !g_localhost_via_proxy && dest_first_octet == 127)
                        action = RULE_ACTION_DIRECT;

                    // Override PROXY to DIRECT for critical IPs and ports
                    if (action == RULE_ACTION_PROXY && is_broadcast_or_multicast(dest_ip))
                        action = RULE_ACTION_DIRECT;

                    // Override PROXY to DIRECT for DHCP ports (67=server, 68=client)
                    if (action == RULE_ACTION_PROXY && (dest_port == 67 || dest_port == 68))
                        action = RULE_ACTION_DIRECT;

                    // only log if callback is set
                    // reuse pid from check_process_rule
                    // CLI use no log flag
                    if (g_connection_callback != NULL && pid > 0)
                    {
                        char process_name[MAX_PROCESS_NAME];

                        if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
                        {
                            if (!is_connection_already_logged(pid, dest_ip, dest_port, action))
                            {
                                char dest_ip_str[32];
                                format_ip_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));

                                char proxy_info[128];
                                if (action == RULE_ACTION_PROXY)
                                {
                                    PROXY_CONFIG *pcfg = find_proxy_config(proxy_config_id);
                                    if (pcfg != NULL)
                                        snprintf(proxy_info, sizeof(proxy_info), "Proxy %s://%s:%d (UDP)",
                                            pcfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                                            pcfg->host, pcfg->port);
                                    else
                                        snprintf(proxy_info, sizeof(proxy_info), "Proxy (UDP)");
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

                                if (g_traffic_logging_enabled)
                                {
                                    add_logged_connection(pid, dest_ip, dest_port, action);
                                }
                            }
                        }
                    }

                    if (action == RULE_ACTION_BLOCK)
                    {
                        continue;
                    }

                    if (action == RULE_ACTION_PROXY)
                    {
                        add_connection(src_port, TRUE, src_ip, dest_ip, dest_port, proxy_config_id);

                        // redirect to UDP relay server at 127.0.0.1:34011
                        udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);

                        // check if source is localhost
                        BYTE src_first_octet = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                        BOOL src_is_loopback = (src_first_octet == 127);

                        if (src_is_loopback)
                        {
                            ip_header->DstAddr = htonl(INADDR_LOOPBACK);
                        }
                        else
                        {
                            UINT32 temp_addr = ip_header->DstAddr;
                            ip_header->DstAddr = ip_header->SrcAddr;
                            ip_header->SrcAddr = temp_addr;
                            addr.Outbound = FALSE;
                        }
                        // for loopback we need keep as outbound (127.x.x.x -> 127.0.0.1)

                    }
                    else
                    {
                        // DIRECT (or no matching rule): the packet is unmodified, so send it
                        // as-is. Recomputing checksums on an untouched packet is wasteful and
                        // can conflict with NIC checksum offload on some drivers (see #161).
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }
                }
            }
            else
            {
                if (udp_header->DstPort != htons(LOCAL_UDP_RELAY_PORT))
                {
                    // Snoop DNS responses to build the IP→hostname cache used by
                    // socks5_connect_domain() so that SOCKS5 proxies receive the
                    // original hostname instead of a bare IP (issue #138).
                    if (ntohs(udp_header->SrcPort) == 53)
                    {
                        const UINT8 *udp_payload = (const UINT8 *)udp_header + sizeof(WINDIVERT_UDPHDR);
                        int udp_payload_len = (int)(ntohs(udp_header->Length) - sizeof(WINDIVERT_UDPHDR));
                        if (udp_payload_len > 0)
                            snoop_dns_response(udp_payload, udp_payload_len);
                    }
                    // Unmodified packet no checksum needed
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }

            }

            // Modified UDP packet calculate checksums
            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
            WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }        // TCP packets only from here
        if (tcp_header == NULL)
            continue;

        if (addr.Outbound)
        {
            // per port decision fast-path.
            // Once check_process_rule() has run for a source port and decided DIRECT,
            // every subsequent packet from that port takes this branch one bitmap
            // read 5 cycle + WinDivertSend, with zero kernel calls
            // FIN/RST clears the cache entry so port can be reused safely
            // Part of this taken from Cluade to fix windivert packet error
            {
                UINT16 sp = ntohs(tcp_header->SrcPort);

                // A fresh SYN starts a new connection that may be reusing an ephemeral
                // port whose previous owner has closed. Evict any PID cached for this
                // port so the rule decision is re-derived against the correct current
                // process instead of a stale one (prevents wrong-app rule matching for
                // up to PID_CACHE_TTL_MS after a port is recycled).
                if (tcp_header->Syn && !tcp_header->Ack)
                    remove_cached_pid(ip_header->SrcAddr, sp, FALSE);

                if (port_is_decided(sp))
                {
                    if (tcp_header->Fin || tcp_header->Rst)
                        port_clear(sp);
                    if (port_is_direct(sp))
                    {
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }
                    // For PROXY/BLOCK decisions the connection was already added on the
                    // first packet; subsequent packets are handled by is_connection_tracked
                    // below so just fall through.
                }
            }

            if (tcp_header->SrcPort == htons(g_local_relay_port))
            {
                UINT16 dst_port = ntohs(tcp_header->DstPort);
                UINT32 orig_dest_ip;
                UINT16 orig_dest_port;

                if (get_connection(dst_port, FALSE, &orig_dest_ip, &orig_dest_port))
                    tcp_header->SrcPort = htons(orig_dest_port);

                BYTE src_first = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                BYTE dst_first = (ntohl(ip_header->DstAddr) >> 24) & 0xFF;
                BOOL is_loopback = (src_first == 127 && dst_first == 127);

                if (!is_loopback)
                {
                    UINT32 temp_addr = ip_header->DstAddr;
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }

                if (tcp_header->Fin || tcp_header->Rst)
                    remove_connection(dst_port, FALSE);
            }
            else if (is_connection_tracked(ntohs(tcp_header->SrcPort), FALSE))
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);

                if (tcp_header->Fin || tcp_header->Rst)
                {
                    remove_connection(src_port, FALSE);
                    port_clear(src_port);
                }

                tcp_header->DstPort = htons(g_local_relay_port);

                BYTE src_first = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                BYTE dst_first = (ntohl(ip_header->DstAddr) >> 24) & 0xFF;
                BOOL is_loopback = (src_first == 127 && dst_first == 127);

                if (!is_loopback)
                {
                    UINT32 temp_addr = ip_header->DstAddr;
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }

            }
            else
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);
                UINT32 src_ip = ip_header->SrcAddr;
                UINT32 orig_dest_ip = ip_header->DstAddr;
                UINT16 orig_dest_port = ntohs(tcp_header->DstPort);

                // avoid rule pocess and packet process if no rules
                if (!g_has_active_rules && g_connection_callback == NULL)
                {
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }

                RuleAction action;
                DWORD pid = 0;
                UINT32 proxy_config_id = 0;

                action = check_process_rule(src_ip, src_port, orig_dest_ip, orig_dest_port, FALSE, &pid, &proxy_config_id);

                BYTE orig_dest_first_octet = (orig_dest_ip >> 0) & 0xFF;
                if (action == RULE_ACTION_PROXY && !g_localhost_via_proxy && orig_dest_first_octet == 127)
                    action = RULE_ACTION_DIRECT;

                // Override PROXY to DIRECT for criticl ips
                if (action == RULE_ACTION_PROXY && is_broadcast_or_multicast(orig_dest_ip))
                    action = RULE_ACTION_DIRECT;

                // only new TCP/SYN inital fist packet
                if (g_connection_callback != NULL && tcp_header->Syn && !tcp_header->Ack && pid > 0)
                {
                    char process_name[MAX_PROCESS_NAME];
                    if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
                    {
                        if (!is_connection_already_logged(pid, orig_dest_ip, orig_dest_port, action))
                        {
                            char dest_ip_str[32];
                            snprintf(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
                                (orig_dest_ip >> 0) & 0xFF, (orig_dest_ip >> 8) & 0xFF,
                                (orig_dest_ip >> 16) & 0xFF, (orig_dest_ip >> 24) & 0xFF);

                            char proxy_info[128];
                            if (action == RULE_ACTION_PROXY)
                            {
                                PROXY_CONFIG *pcfg = find_proxy_config(proxy_config_id);
                                if (pcfg != NULL)
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy %s://%s:%d",
                                        pcfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                                        pcfg->host, pcfg->port);
                                else
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy");
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

                            if (g_traffic_logging_enabled)
                            {
                                add_logged_connection(pid, orig_dest_ip, orig_dest_port, action);
                            }
                        }
                    }
                }

                if (action == RULE_ACTION_DIRECT)
                {
                    // Cache this decision so all subsequent packets from this port
                    // fast-path at the top of the outbound branch (zero kernel calls).
                    port_set_direct(src_port);
                    // Unmodified packet no checksum needed
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }
                else if (action == RULE_ACTION_BLOCK)
                {
                    port_set_decided(src_port);  // mark decided (not direct) so we don't re-run rule check
                    // Drop the packet - don't send it anywhere
                    continue;
                }
                else if (action == RULE_ACTION_PROXY)
            {
                add_connection(src_port, FALSE, src_ip, orig_dest_ip, orig_dest_port, proxy_config_id);
                // Mark this port as decided (not direct) so subsequent packets from
                // the same source port skip the rule check.  The is_connection_tracked
                // branch above handles the actual per-packet redirect.
                port_set_decided(src_port);

                tcp_header->DstPort = htons(g_local_relay_port);

                // check if this is localhost -> localhost traffic
                BYTE src_first_octet = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                BYTE dst_first_octet = (ntohl(ip_header->DstAddr) >> 24) & 0xFF;
                BOOL is_loopback_to_loopback = (src_first_octet == 127 && dst_first_octet == 127);

                if (is_loopback_to_loopback)
                {
                    // for localhost -> localhost just change port, keep as outbound
                    // dont swap IPs Windows loopback routing needs both to stay 127.x.x.x
                    log_message("[PACKET] Loopback redirect: 127.x.x.x:%d -> 127.x.x.x:%d (relay port %d)",
                        ntohs(tcp_header->SrcPort), orig_dest_port, g_local_relay_port);
                    // addr.Outbound stays TRUE
                }
                else
                {
                    // for normal traffic: swap IPs and mark as inbound (standard relay behavior)
                    UINT32 temp_addr = ip_header->DstAddr;
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }
                }
            }
        }
        else
        {
            if (tcp_header->DstPort != htons(g_local_relay_port))
            {
                // Unmodified return packet no checksum needed
                WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }
        }

        // Modified TCP packet calculate checksums
        WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
        if (!WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr))
        {
            log_message("Failed to send packet (%lu)", GetLastError());
        }
    }

    return 0;
}

PROXYBRIDGE_API void ProxyBridge_SetLocalhostViaProxy(BOOL enable)
{
    g_localhost_via_proxy = enable;
    log_message("Localhost routing: %s (most proxies block localhost for SSRF prevention)", enable ? "via proxy" : "direct");
}

PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback)
{
    g_log_callback = callback;
}

PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback)
{
    g_connection_callback = callback;
}

PROXYBRIDGE_API void ProxyBridge_SetTrafficLoggingEnabled(BOOL enable)
{
    g_traffic_logging_enabled = enable;
    if (!enable)
    {
        clear_logged_connections();
    }
}

PROXYBRIDGE_API void ProxyBridge_ClearConnectionLogs(void)
{
    clear_logged_connections();
    log_message("Connection logs cleared");
}

// Dedicated cleanup thread - runs independently without blocking packet processing
DWORD WINAPI cleanup_worker(LPVOID arg)
{
    while (running)
    {
        Sleep(30000);  // 30 seconds
        if (running)
        {
            cleanup_stale_connections();
            cleanup_stale_pid_cache();
            cleanup_stale_dns_cache();
        }
    }
    return 0;
}

PROXYBRIDGE_API BOOL ProxyBridge_Start(void)
{
    char filter[FILTER_BUFFER_SIZE];
    INT16 priority = 123;

    if (running)
        return FALSE;

    InitializeSRWLock(&lock);
    dns_cache_init();

    // If domain rules were configured before start, flush the OS DNS cache so the very
    // first connections re-resolve on the wire and populate our IP->hostname snoop cache.
    if (g_has_domain_rules)
        flush_dns_resolver_cache();

    running = TRUE;

    proxy_thread = CreateThread(NULL, 1, local_proxy_server, NULL, 0, NULL);
    if (proxy_thread == NULL)
    {
        running = FALSE;
        return FALSE;
    }

    // Start cleanup thread to avoid blocking packet processing
    cleanup_thread = CreateThread(NULL, 1, cleanup_worker, NULL, 0, NULL);
    if (cleanup_thread == NULL)
    {
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    if (any_socks5_config())
    {
        udp_relay_thread = CreateThread(NULL, 1, udp_relay_server, NULL, 0, NULL);
        if (udp_relay_thread == NULL)
        {
            running = FALSE;
            WaitForSingleObject(cleanup_thread, INFINITE);
            CloseHandle(cleanup_thread);
            cleanup_thread = NULL;
            WaitForSingleObject(proxy_thread, INFINITE);
            CloseHandle(proxy_thread);
            proxy_thread = NULL;
            return FALSE;
        }
    }

    Sleep(500);

    // "not impostor" ensures WinDivert never re-captures packets it already injected.
    // Without this, each WinDivertSend re-enters the capture queue, creating
    // re-injection loops that delay delivery by seconds and cause DTLS handshake
    // failures.  With "not impostor", injected packets bypass the driver entirely
    // and flow directly to the OS - zero extra hops, no loops.
    // DHCP is deliberately excluded at the filter level so those packets never enter
    // ProxyBridge at all. DHCP is link-local broadcast (0.0.0.0 -> 255.255.255.255) and
    // #161  DHCPv4: client 68 / server 67     DHCPv6: client 546 / server 547
    snprintf(filter, sizeof(filter),
        "not impostor and ("
        "(tcp and (outbound or loopback or (tcp.DstPort == %d or tcp.SrcPort == %d))) or "
        "(udp and (outbound or loopback or (udp.DstPort == %d or udp.SrcPort == %d)) and "
            "udp.SrcPort != 67 and udp.DstPort != 67 and udp.SrcPort != 68 and udp.DstPort != 68) or "
        "(udp and not outbound and udp.SrcPort == 53) or "
        "(ipv6 and udp and not outbound and udp.SrcPort == 53) or "
        "(ipv6 and tcp and (outbound or loopback or (tcp.DstPort == %d or tcp.SrcPort == %d))) or "
        "(ipv6 and udp and (outbound or loopback or (udp.DstPort == %d or udp.SrcPort == %d)) and "
            "udp.SrcPort != 546 and udp.DstPort != 546 and udp.SrcPort != 547 and udp.DstPort != 547))",
        g_local_relay_port, g_local_relay_port, LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT,
        g_local_relay_port, g_local_relay_port, LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT);

    // Note: Added 'loopback' to filter to capture localhost (127.x.x.x) traffic
    // This enables proxying local connections for MITM scenarios
    windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
    if (windivert_handle == INVALID_HANDLE_VALUE)
    {
        DWORD wd_err = GetLastError();
        switch (wd_err)
        {
            case 2:    // ERROR_FILE_NOT_FOUND
                log_message("Failed to open WinDivert (%lu): WinDivert64.sys not found - it may have been quarantined or deleted by antivirus. Whitelist WinDivert64.sys and ProxyBridgeCore.dll in your AV and reinstall.", wd_err);
                break;
            case 5:    // ERROR_ACCESS_DENIED
                log_message("Failed to open WinDivert (%lu): Access denied - make sure ProxyBridge is running as Administrator.", wd_err);
                break;
            case 577:  // ERROR_INVALID_IMAGE_HASH - driver signature check failed
                log_message("Failed to open WinDivert (%lu): Driver signature verification failed - WinDivert64.sys may have been modified or blocked by security software. Reinstall ProxyBridge.", wd_err);
                break;
            case 1058: // ERROR_SERVICE_DISABLED
                log_message("Failed to open WinDivert (%lu): A stale WinDivert driver entry from a previous install is marked disabled. Reinstall ProxyBridge to fix it, or manually delete the registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDivert", wd_err);
                break;
            case 1275: // ERROR_DRIVER_BLOCKED
                log_message("Failed to open WinDivert (%lu): WinDivert64.sys is blocked by Windows security policy or antivirus (BYOVD protection). Whitelist WinDivert64.sys in your security software.", wd_err);
                break;
            default:
                log_message("Failed to open WinDivert (%lu): Ensure ProxyBridge is installed correctly and running as Administrator.", wd_err);
                break;
        }
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    // WINDIVERT_PARAM_QUEUE_LENGTH: max packets in queue (range 32–16384).
    // Under heavy upload the kernel enqueues bursts of outbound packets faster
    // than the 4 packet threads can drain them; a full queue drops arriving
    // packets → TCP sees loss → retransmit + congestion-window halving.
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    // WINDIVERT_PARAM_QUEUE_TIME: ms a packet waits before being dropped
    // (range 100–16000, default 2000).  The old value of 8 ms was below the
    // minimum (100 ms) and caused aggressive packet drops under any sustained
    // upload load, directly producing the 40-60% upload throughput loss.
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    // WINDIVERT_PARAM_QUEUE_SIZE: max total bytes in queue (range 65535–33553920).
    // Raise to the maximum so a burst of large packets never hits a byte cap.
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_SIZE, 33553920);

    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        packet_thread[i] = CreateThread(NULL, 0, packet_processor, NULL, 0, NULL);
        if (packet_thread[i] == NULL)
        {
            running = FALSE;
            for (int j = 0; j < i; j++)
            {
                if (packet_thread[j] != NULL)
                {
                    WaitForSingleObject(packet_thread[j], 5000);
                    CloseHandle(packet_thread[j]);
                    packet_thread[j] = NULL;
                }
            }
            WinDivertClose(windivert_handle);
            windivert_handle = INVALID_HANDLE_VALUE;
            WaitForSingleObject(proxy_thread, INFINITE);
            CloseHandle(proxy_thread);
            proxy_thread = NULL;
            return FALSE;
        }
    }

    update_has_active_rules();

    log_message("ProxyBridge started");
    log_message("Local relay: localhost:%d", g_local_relay_port);
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        log_message("Proxy config ID %u: %s %s:%u",
            cfg->config_id,
            cfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
            cfg->host, cfg->port);
    }
    if (g_proxy_config_count == 0)
        log_message("Warning: No proxy configs configured");

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
        WinDivertShutdown(windivert_handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }

    // process alll packets before we stop, make sure packets are not dropped
    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        if (packet_thread[i] != NULL)
        {
            WaitForSingleObject(packet_thread[i], 1000);  // 1 second timeout
            CloseHandle(packet_thread[i]);
            packet_thread[i] = NULL;
        }
    }

    if (proxy_thread != NULL)
    {
        WaitForSingleObject(proxy_thread, 1000);  // 1 second timeout
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
    }

    if (cleanup_thread != NULL)
    {
        WaitForSingleObject(cleanup_thread, 1000);  // 1 second timeout
        CloseHandle(cleanup_thread);
        cleanup_thread = NULL;
    }

    if (udp_relay_thread != NULL)
    {
        WaitForSingleObject(udp_relay_thread, 1000);  // 1 second timeout
        CloseHandle(udp_relay_thread);
        udp_relay_thread = NULL;
    }

    AcquireSRWLockExclusive(&lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        while (connection_hash_table[i] != NULL)
        {
            CONNECTION_INFO *to_free = connection_hash_table[i];
            connection_hash_table[i] = connection_hash_table[i]->next;
            free(to_free);
        }
    }
    // Entries were freed via the forward table above; just drop the reverse index's
    // dangling bucket pointers so a later Start doesn't walk freed memory.
    memset(connection_rev_table, 0, sizeof(connection_rev_table));
    ReleaseSRWLockExclusive(&lock);

    // Clear logged connections list
    clear_logged_connections();

    clear_pid_cache();

    // Release the reusable owner-PID table scratch buffer (packet thread has stopped).
    free(g_pidtbl_buf);
    g_pidtbl_buf = NULL;
    g_pidtbl_cap = 0;

    // Reset per-port decision cache so stale entries don't carry over
    // if ProxyBridge is stopped and restarted with different rules.
    memset((void*)port_decided_bitmap, 0, sizeof(port_decided_bitmap));
    memset((void*)port_direct_bitmap,  0, sizeof(port_direct_bitmap));

    log_message("ProxyBridge stopped");

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            // Store the PID of the process that loaded this DLL
            g_current_process_id = GetCurrentProcessId();
            // Initialize Winsock here so that resolve_hostname() / getaddrinfo()
            // work correctly when AddProxyConfig is called before any thread
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
            break;
        }
        case DLL_PROCESS_DETACH:
            WSACleanup();
            if (running)
                ProxyBridge_Stop();
            // Close all proxy config UDP sockets
            for (int i = 0; i < g_proxy_config_count; i++)
            {
                PROXY_CONFIG *cfg = &g_proxy_configs[i];
                if (cfg->udp_tcp_ctrl != INVALID_SOCKET)  { closesocket(cfg->udp_tcp_ctrl);  cfg->udp_tcp_ctrl  = INVALID_SOCKET; }
                if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
            }
            AcquireSRWLockExclusive(&g_rules_lock);
            while (rules_list != NULL)
            {
                PROCESS_RULE *to_free = rules_list;
                rules_list = rules_list->next;

                if (to_free->target_hosts != NULL)
                    free(to_free->target_hosts);
                if (to_free->target_ports != NULL)
                    free(to_free->target_ports);
                if (to_free->target_domains != NULL)
                    free(to_free->target_domains);

                free(to_free);
            }
            ReleaseSRWLockExclusive(&g_rules_lock);
            break;
    }
    return TRUE;
}


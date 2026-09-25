void pb_report_connection(DWORD pid, const char *name_override, BOOL is_ipv6, UINT32 dest_ip,
                          const UINT8 dest_ip6[16], UINT16 dest_port, RuleAction action,
                          UINT32 cfg_id, BOOL is_udp, const PROXY_CONFIG *selected_proxy)
{
    ConnectionCallback callback = (ConnectionCallback)InterlockedCompareExchangePointer((PVOID volatile *)&g_connection_callback, NULL, NULL);
    BOOL record = InterlockedCompareExchange((volatile LONG *)&g_traffic_logging_enabled, 0, 0);
    if (callback == NULL && !record) return;
    PB_LOG_KEY key = {0};
    key.pid = pid; key.dest_port = dest_port; key.ipv6 = !!is_ipv6; key.udp = !!is_udp; key.action = action;
    memcpy(key.address, is_ipv6 ? (const void *)dest_ip6 : (const void *)&dest_ip, is_ipv6 ? 16 : 4);
    if (action == RULE_ACTION_PROXY) {
        key.proxy_id = selected_proxy != NULL ? selected_proxy->config_id : cfg_id;
        key.proxy_revision = selected_proxy != NULL ? selected_proxy->revision : 0;
    }
    if (!pb_log_connection_once(&key, record)) return;

    // History stores the numeric identity only. Name/proxy lookup and string
    // formatting are unnecessary when no connection callback consumes them.
    if (callback == NULL) {
        return;
    }

    // Prefer a caller-supplied name (the driver captured it in-kernel, so it survives a process
    // that has already exited); otherwise resolve the live PID.
    char pname[MAX_PROCESS_NAME] = "unknown";
    if (name_override != NULL && name_override[0] != '\0')
        strncpy_s(pname, sizeof(pname), name_override, _TRUNCATE);
    else
        get_process_name_from_pid(pid, pname, sizeof(pname));
    const char *disp = extract_filename(pname);

    char ipstr[64] = "?";
    if (is_ipv6) {
        inet_ntop(AF_INET6, (void *)dest_ip6, ipstr, sizeof(ipstr));
    } else {
        struct in_addr a; a.S_un.S_addr = dest_ip;
        inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
    }

    char info[160];
    const char *u = is_udp ? " (UDP)" : "";
    if (action == RULE_ACTION_PROXY) {
        const PROXY_CONFIG *p = selected_proxy;
        if (p != NULL && p->host[0] != '\0')
            snprintf(info, sizeof(info), "Proxy %s://%s:%u%s",
                     p->type == PROXY_TYPE_HTTP ? "http" : "socks5", p->host, p->port, u);
        else
            snprintf(info, sizeof(info), "Proxy%s", u);
    } else if (action == RULE_ACTION_BLOCK) {
        snprintf(info, sizeof(info), "Blocked%s", u);
    } else {
        snprintf(info, sizeof(info), "Direct%s", u);
    }

    callback(disp, pid, ipstr, dest_port, info);
}


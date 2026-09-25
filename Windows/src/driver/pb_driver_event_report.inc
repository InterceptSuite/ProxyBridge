// Called after event draining and health checks, outside the driver-handle lock.
// Discard only diagnostic preparation when neither connection consumer is active.
static void driver_report_event(const PBDRV_EVENT* e)
{
    if (InterlockedCompareExchangePointer((PVOID volatile *)&g_connection_callback, NULL, NULL) == NULL &&
        !InterlockedCompareExchange((volatile LONG *)&g_traffic_logging_enabled, 0, 0)) return;
    BOOL   is_udp = (e->protocol == IPPROTO_UDP);
    BOOL   is_v6  = (e->family == AF_INET6);
    UINT32 cfg    = 0;
    char   pname[MAX_PROCESS_NAME] = "";
    RuleAction act = RULE_ACTION_DIRECT;

    // Resolve the process name: prefer the live PID (gives the full C:\ path so
    // full-path rules work); fall back to the basename the driver captured at connect
    // time, so a process that already exited still logs correctly (never "unknown").
    if (!get_process_name_from_pid(e->pid, pname, sizeof(pname)) && e->image[0] != 0)
        WideCharToMultiByte(CP_UTF8, 0, e->image, -1, pname, sizeof(pname), NULL, NULL);

    PROXY_CONFIG selected;
    BOOL available = FALSE;
    if (pname[0] != '\0')
        act = pb_select_proxy(pname, is_v6, e->remoteV4, e->remoteV6,
                              e->remotePort, is_udp, &cfg, &selected, &available);

    pb_report_connection(e->pid, pname[0] ? pname : NULL, is_v6, e->remoteV4, e->remoteV6,
                         e->remotePort, act, cfg, is_udp, available ? &selected : NULL);
}

// UI-thread setting publication. The DLL's history switch intentionally does not
// disable callbacks for other API consumers; the GUI must unsubscribe explicitly.
static void ApplyTrafficLogging(void)
{
    InterlockedExchange(&g_connectionLogEnabled, !!g_trafficLog);
    if (!g_trafficLog) g_api.SetConnectionCallback(NULL);
    g_api.SetTrafficLoggingEnabled(g_trafficLog);
    if (g_trafficLog) g_api.SetConnectionCallback(PBConnCb);
}

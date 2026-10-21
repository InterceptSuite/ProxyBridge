#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/auxv.h>
#include "../src/ProxyBridge.h"
#include "../profile/pb_profile.h"
#include "../src/pb_ipc.h"
#include "daemon.h"
#include "../src/pb_unit.h"

#define UPDATE_FEED "https://download.interceptsuite.com/proxybridge.json"

static volatile bool keep_running = false;
static int verbose_level = 0;

static void log_callback(const char* message)
{
    if (verbose_level == 1 || verbose_level == 3)
        printf("[LOG] %s\n", message);
}

static void connection_callback(const char* process_name, uint32_t pid, const char* dest_ip, uint16_t dest_port, const char* protocol, const char* proxy_info)
{
    if (verbose_level == 2 || verbose_level == 3)
        printf("[CONN] %s (PID:%u) -> %s:%u via %s%s\n", process_name, pid, dest_ip, dest_port, proxy_info, protocol && !strcmp(protocol, "UDP") ? " (UDP)" : "");
}

static void signal_handler(int sig)
{
    (void)sig;
    keep_running = false;
}

static void show_banner(void)
{
    printf("\n");
    printf("  ____                        ____       _     _            \n");
    printf(" |  _ \\ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___ \n");
    printf(" | |_) | '__/ _ \\ \\/ / | | | |  _ \\| '__| |/ _` |/ _` |/ _ \\\n");
    printf(" |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/\n");
    printf(" |_|   |_|  \\___/_/\\_\\\\__, | |____/|_|  |_|\\__,_|\\__, |\\___|\n");
    printf("                      |___/                      |___/  V%s\n", PROXYBRIDGE_VERSION);
    printf("\n");
    printf("  Universal proxy client for Linux applications\n");
    printf("\n");
    printf("\tAuthor: Sourav Kalal/InterceptSuite\n");
    printf("\tGitHub: https://github.com/InterceptSuite/ProxyBridge\n");
    printf("\n");
}

static void show_help(void)
{
    show_banner();
    printf("Options:\n");
    printf("  --profile <path>     Path to a .pbprofile file exported from the GUI, or the name of a\n");
    printf("                       profile saved by the GUI (the Profile menu)\n\n");
    printf("  --verbose <0-3>      Logging verbosity\n");
    printf("                         0 - Silent (default)\n");
    printf("                         1 - Log messages only\n");
    printf("                         2 - Connection events only\n");
    printf("                         3 - Both logs and connections\n\n");
    printf("  --daemon             Run as the ProxyBridge service: owns the engine and the profiles, and lets the\n");
    printf("                       window (which then needs no root) control it. Used by proxybridge.service\n");
    printf("  --print-unit <path>  Print the systemd unit that runs <path> --daemon (used by the installer)\n");
    printf("  --socket <path>      With --daemon: the control socket (default %s)\n\n", PB_IPC_SOCKET_PATH);
    printf("  --version            Show version information\n");
    printf("  -?, -h, --help       Show help\n\n");
    printf("Commands:\n");
    printf("  --update             Check for updates and print where to download the latest version\n");
    printf("                       (does not require root)\n\n");
    printf("Examples:\n");
    printf("  sudo ProxyBridge --profile ~/myconfig.pbprofile\n");
    printf("  sudo ProxyBridge --profile work --verbose 2\n\n");
    printf("Notes:\n");
    printf("  --profile requires root and a Linux kernel >= 5.11 with BTF and cgroup v2 (eBPF datapath)\n");
    printf("  Press Ctrl+C to stop ProxyBridge cleanly\n\n");
}

static bool is_https(const char* url)
{
    if (!url || strncmp(url, "https://", 8) != 0)
        return false;
    for (const char* c = url; *c; c++)
        if ((unsigned char)*c < 33 || *c > 126 || *c == '"' || *c == '\'' || *c == '`' || *c == '\\')
            return false;
    return true;
}

/* --update: ask the feed with curl and print what it says. Nothing is downloaded or run. */
static int check_update(void)
{
    const char* feed = getauxval(AT_SECURE) ? NULL : getenv("PROXYBRIDGE_UPDATE_FEED");   /* a mirror, or a local file in tests; never under setuid */
    if (!feed || !*feed)
        feed = UPDATE_FEED;
    int fds[2];
    if (pipe(fds) != 0)
    {
        perror("pipe");
        return 1;
    }
    pid_t pid = fork();
    if (pid == 0)
    {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        execlp("curl", "curl", "-sS", "-m", "15", "--proto", "=https,file", "-H", "User-Agent: ProxyBridge-UpdateChecker", "--", feed, (char*)NULL);
        _exit(127);
    }
    close(fds[1]);
    static char json[65536];
    size_t n = 0;
    ssize_t r;
    while (pid > 0 && n < sizeof(json) - 1 && (r = read(fds[0], json + n, sizeof(json) - 1 - n)) > 0)
        n += (size_t)r;
    close(fds[0]);
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0 || n == 0)
    {
        fprintf(stderr, "ERROR: Update check failed (could not fetch %s)\n", feed);
        return 1;
    }
    char *version, *download, *notes;
    if (pbp_update_parse(json, n, &version, &download, &notes) != 0)
    {
        fprintf(stderr, "ERROR: Update check failed (the feed has no Linux version)\n");
        return 1;
    }
    printf("Current version: %s\n", PROXYBRIDGE_VERSION);
    printf("Latest version:  %s\n", version);
    if (!pbp_version_newer(version, PROXYBRIDGE_VERSION))
        printf("You are using the latest version.\n");
    else
    {
        printf("A newer version is available.\n");
        if (is_https(notes))
            printf("Release notes:   %s\n", notes);
        if (is_https(download))
            printf("Download:        %s\n", download);
        if (!is_https(notes) && !is_https(download))
            printf("(The feed has no safe https link; see https://github.com/InterceptSuite/ProxyBridge/releases)\n");
    }
    free(version);
    free(download);
    free(notes);
    return 0;
}

static bool is_root(void)
{
    return getuid() == 0;
}

int main(int argc, char *argv[])
{
    const char* profile_arg = NULL;
    bool daemon_mode = false;
    const char* socket_arg = PB_IPC_SOCKET_PATH;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-?") == 0)
        {
            show_help();
            return 0;
        }
        else if (strcmp(argv[i], "--version") == 0)
        {
            printf("ProxyBridge CLI V%s\n", PROXYBRIDGE_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--update") == 0)
        {
            return check_update();
        }
        else if (strcmp(argv[i], "--daemon") == 0)
        {
            daemon_mode = true;
        }
        else if (strcmp(argv[i], "--print-unit") == 0 && i + 1 < argc)
        {
            const char* why = NULL;
            char* text = pb_unit_text(argv[++i], &why);
            if (!text)
            {
                fprintf(stderr, "ERROR: %s\n", why ? why : "cannot build the unit");
                return 1;
            }
            fputs(text, stdout);
            free(text);
            return 0;
        }
        else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
        {
            socket_arg = argv[++i];
        }
        else if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc)
        {
            profile_arg = argv[++i];
        }
        else if (strcmp(argv[i], "--verbose") == 0 && i + 1 < argc)
        {
            const char* v = argv[++i];
            if (strlen(v) != 1 || v[0] < '0' || v[0] > '3')
            {
                fprintf(stderr, "ERROR: Verbose level must be 0-3\n");
                return 1;
            }
            verbose_level = v[0] - '0';
        }
        else
        {
            fprintf(stderr, "ERROR: Unknown option '%s'\n", argv[i]);
            fprintf(stderr, "Use --help for usage information\n");
            return 1;
        }
    }

    if (daemon_mode)
    {
        if (profile_arg)
        {
            fprintf(stderr, "ERROR: --daemon runs the profile the window made active; it does not take --profile.\n");
            return 1;
        }
        return pb_daemon_run(socket_arg, verbose_level);
    }

    if (!profile_arg)
    {
        fprintf(stderr, "ERROR: No profile specified.\n");
        fprintf(stderr, "Usage: ProxyBridge --profile <file.pbprofile>\n\n");
        return 1;
    }

    char err[256];
    char* path = pbp_resolve(pbp_config_dir(), profile_arg);
    struct pbp_profile prof;
    if (!path)
    {
        fprintf(stderr, "ERROR: Invalid profile '%s'\n", profile_arg);
        return 1;
    }
    printf("Loading profile: %s\n", path);
    if (pbp_load_file(path, &prof, err, sizeof(err)) != 0)
    {
        fprintf(stderr, "ERROR: %s\n", err);
        free(path);
        return 1;
    }

    struct stat st;
    bool has_secret = false;
    for (size_t i = 0; i < prof.nproxies; i++)
        if (prof.proxies[i].pass[0])
            has_secret = true;
    if (has_secret && stat(path, &st) == 0 && (st.st_mode & 077))
        fprintf(stderr, "WARNING: %s holds proxy credentials but other users can read it (chmod 600 recommended)\n", path);
    free(path);

    size_t enabled = 0;
    bool needs_proxy = false;
    for (size_t i = 0; i < prof.nrules; i++)
        if (prof.rules[i].enabled)
        {
            enabled++;
            if (prof.rules[i].action == RULE_ACTION_PROXY)
                needs_proxy = true;
        }
    if (enabled == 0)
    {
        fprintf(stderr, "ERROR: Profile contains no enabled rules.\n");
        pbp_free(&prof);
        return 1;
    }
    if (needs_proxy && prof.nproxies == 0)
    {
        fprintf(stderr, "ERROR: A rule uses a proxy but the profile has no proxy server.\n");
        pbp_free(&prof);
        return 1;
    }

    show_banner();

    if (!is_root())
    {
        printf("\033[31m\nERROR: ProxyBridge requires root privileges!\033[0m\n");
        printf("Please run this application with sudo or as root.\n\n");
        pbp_free(&prof);
        return 1;
    }

    ProxyBridge_SetLogCallback(verbose_level == 1 || verbose_level == 3 ? log_callback : NULL);
    ProxyBridge_SetConnectionCallbackEx(verbose_level == 2 || verbose_level == 3 ? connection_callback : NULL);
    ProxyBridge_SetTrafficLoggingEnabled(verbose_level > 0);
    ProxyBridge_SetDnsViaProxy(prof.dns_via_proxy);
    ProxyBridge_SetLogEveryConnection(prof.log_every);

    uint32_t ids[PBP_MAX_PROXIES + 1] = { 0 };
    printf("Proxies: %zu\n", prof.nproxies);
    for (size_t i = 0; i < prof.nproxies; i++)
    {
        const struct pbp_proxy* p = &prof.proxies[i];
        ids[i] = ProxyBridge_AddProxy(p->name, p->type ? PROXY_TYPE_SOCKS5 : PROXY_TYPE_HTTP, p->host, p->port, p->user, p->pass, err, sizeof(err));
        if (!ids[i])
        {
            fprintf(stderr, "ERROR: Proxy '%s' (%s:%u): %s\n", p->name, p->host, p->port, err);
            pbp_free(&prof);
            return 1;
        }
        if (!p->send_domain)
            ProxyBridge_SetProxySendDomain(ids[i], false);
        printf("  [%zu] %s %s://%s:%u%s%s\n", i + 1, p->name, p->type ? "socks5" : "http", p->host, p->port,
               p->user[0] ? " (auth)" : "", p->send_domain ? "" : " (dns:local)");
    }
    if (prof.default_proxy_id)
        for (size_t i = 0; i < prof.nproxies; i++)
            if (prof.proxies[i].id == prof.default_proxy_id)
                ProxyBridge_SetDefaultProxy(ids[i]);
    printf("DNS via Proxy: %s\n", prof.dns_via_proxy ? "Enabled" : "Disabled");

    printf("Rules: %zu\n", enabled);
    for (size_t i = 0; i < prof.nrules; i++)
    {
        const struct pbp_rule* r = &prof.rules[i];
        if (!r->enabled)
            continue;
        uint32_t proxy_id = 0;
        if (r->action == RULE_ACTION_PROXY && r->proxy_id)
            for (size_t k = 0; k < prof.nproxies; k++)
                if (prof.proxies[k].id == r->proxy_id)
                    proxy_id = ids[k];
        uint32_t rule_id = ProxyBridge_AddRule(r->process, r->hosts, r->ports, (RuleProtocol)r->protocol, (RuleAction)r->action, proxy_id, err, sizeof(err));
        if (!rule_id)
        {
            fprintf(stderr, "  ERROR: Rule %zu (%s:%s:%s): %s\n", i + 1, r->process, r->hosts, r->ports, err);
            pbp_free(&prof);
            return 1;
        }
        if (r->localhost && r->action == RULE_ACTION_PROXY)
            ProxyBridge_SetRuleLocalhost(rule_id, true);
        printf("  [%u] %s:%s:%s:%s -> %s%s\n", rule_id, r->process, r->hosts, r->ports,
               r->protocol == 0 ? "TCP" : r->protocol == 1 ? "UDP" : "BOTH",
               r->action == RULE_ACTION_PROXY ? "PROXY" : r->action == RULE_ACTION_DIRECT ? "DIRECT" : "BLOCK",
               r->localhost && r->action == RULE_ACTION_PROXY ? " (+localhost)" : "");
    }
    pbp_free(&prof);

    if (!ProxyBridge_Start())
    {
        fprintf(stderr, "ERROR: Failed to start ProxyBridge (run with --verbose 1 for details)\n");
        return 1;
    }

    keep_running = true;
    printf("\nProxyBridge started. Press Ctrl+C to stop...\n\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while (keep_running)
        sleep(1);

    ProxyBridge_Stop();
    printf("ProxyBridge stopped.\n");
    return 0;
}

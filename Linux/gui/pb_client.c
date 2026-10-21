#define PBC_IMPL
#include "gui.h"
#include "gui_boot.h"
#include "pb_client.h"
#include "pb_ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

// ---- connection ------------------------------------------------------------------------------------------------------------
#define MAX_PENDING 16

struct pending {
    bool used, done, ok;
    char id[24];
    char **fields;              // result fields (after ok/err)
    unsigned nfields;
    GQueue *lines;              // streamed lines (proxy test), consumed by the thread that waits
};

static struct {
    int fd;
    bool service;               // service mode (was connected at least once)
    bool alive;
    bool engine_running;
    pthread_t reader;
    bool reader_started;
    pthread_mutex_t mu;         // everything below and the pending table
    pthread_cond_t cv;
    pthread_mutex_t send_mu;
    unsigned long next_id;
    struct pending pend[MAX_PENDING];
    LogCallback log_cb;
    ConnectionCallbackEx conn_cb;
    void (*lost_cb)(void);
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
} C = { .fd = -1, .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .send_mu = PTHREAD_MUTEX_INITIALIZER };

bool pbc_is_service(void) { return C.service; }
bool pbc_alive(void) { return C.service && C.alive; }
bool pbc_service_engine_running(void) { return C.engine_running; }
void pbc_set_lost_callback(void (*cb)(void)) { C.lost_cb = cb; }

static void free_pending_fields(struct pending *p)
{
    for (unsigned i = 0; i < p->nfields; i++) g_free(p->fields[i]);
    g_free(p->fields);
    p->fields = NULL;
    p->nfields = 0;
}

static void *reader_main(void *arg)
{
    (void)arg;
    for (;;) {
        pb_msg m;
        int rc = pb_ipc_recv(C.fd, &m);
        if (rc != 0) break;
        if (m.n >= 2 && !strcmp(m.f[0], "e")) {
            pthread_mutex_lock(&C.mu);
            LogCallback lcb = C.log_cb;
            ConnectionCallbackEx ccb = C.conn_cb;
            pthread_mutex_unlock(&C.mu);
            if (!strcmp(m.f[1], "log") && m.n >= 3 && lcb) lcb(m.f[2]);
            else if (!strcmp(m.f[1], "conn") && m.n >= 8 && ccb) {
                uint64_t pid = 0, port = 0;
                for (const char *p = m.f[3]; *p >= '0' && *p <= '9'; p++) pid = pid * 10 + (uint64_t)(*p - '0');
                for (const char *p = m.f[5]; *p >= '0' && *p <= '9'; p++) port = port * 10 + (uint64_t)(*p - '0');
                ccb(m.f[2], (uint32_t)pid, m.f[4], (uint16_t)port, m.f[6], m.f[7]);
            }
        } else if (m.n >= 3 && !strcmp(m.f[0], "r")) {
            pthread_mutex_lock(&C.mu);
            bool refusal = !strcmp(m.f[1], "0");
            for (int i = 0; i < MAX_PENDING; i++) {
                struct pending *p = &C.pend[i];
                if (!p->used || p->done) continue;
                if (!refusal && strcmp(p->id, m.f[1]) != 0) continue;
                if (!strcmp(m.f[2], "line") && m.n >= 4) {
                    g_queue_push_tail(p->lines, g_strdup(m.f[3]));
                } else {
                    p->ok = !strcmp(m.f[2], "ok");
                    p->nfields = m.n - 3;
                    p->fields = g_new0(char *, p->nfields ? p->nfields : 1);
                    for (unsigned k = 0; k < p->nfields; k++) p->fields[k] = g_strndup(m.f[3 + k], m.len[3 + k]);
                    p->done = true;
                }
            }
            pthread_cond_broadcast(&C.cv);
            pthread_mutex_unlock(&C.mu);
        }
        pb_msg_free(&m);
    }
    pthread_mutex_lock(&C.mu);
    C.alive = false;
    pthread_cond_broadcast(&C.cv);
    pthread_mutex_unlock(&C.mu);
    if (C.lost_cb) C.lost_cb();
    return NULL;
}

// One synchronous exchange on a fresh socket, before the reader thread exists
static int handshake(int fd, char *err, size_t errn, bool *running)
{
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (pb_ipc_sendv(fd, "q", "1", "hello", "1", (char *)NULL) != 0) { snprintf(err, errn, "the ProxyBridge service closed the connection"); return PBC_REFUSED; }
    pb_msg m;
    if (pb_ipc_recv(fd, &m) != 0) { snprintf(err, errn, "the ProxyBridge service did not answer"); return PBC_REFUSED; }
    int rc = PBC_REFUSED;
    if (m.n >= 3 && !strcmp(m.f[0], "r") && !strcmp(m.f[2], "ok") && m.n >= 6) {
        *running = !strcmp(m.f[4], "1");
        rc = PBC_CONNECTED;
    } else {
        snprintf(err, errn, "%s", m.n >= 4 ? m.f[3] : "the ProxyBridge service refused the connection");
    }
    pb_msg_free(&m);
    tv.tv_sec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return rc;
}

static int open_connection(const char *path, int *fd_out, bool *running, char *err, size_t errn)
{
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof a.sun_path) { snprintf(err, errn, "the socket path is too long"); return PBC_REFUSED; }
    strcpy(a.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { snprintf(err, errn, "%s", strerror(errno)); return PBC_REFUSED; }
    // Not a plain blocking connect: this runs on the window's main loop when it reconnects, and a service whose queue is full must not
    // freeze the window.
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int cr = connect(fd, (struct sockaddr *)&a, sizeof a);
    if (cr != 0 && (errno == EAGAIN || errno == EINPROGRESS)) {
        struct pollfd pf = { .fd = fd, .events = POLLOUT };
        if (poll(&pf, 1, 3000) == 1) {
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
            if (soerr == 0) cr = 0; else errno = soerr;
        } else {
            errno = ETIMEDOUT;
        }
    }
    if (cr == 0) fcntl(fd, F_SETFL, fl);
    if (cr != 0) {
        int e = errno;
        close(fd);
        if (e == ENOENT || e == ECONNREFUSED) { snprintf(err, errn, "the ProxyBridge service is not running"); return PBC_NO_SERVICE; }
        if (e == EACCES || e == EPERM) { snprintf(err, errn, "no permission to use the ProxyBridge service socket %s", path); return PBC_REFUSED; }
        snprintf(err, errn, "cannot connect to %s: %s", path, strerror(e));
        return PBC_REFUSED;
    }
    // A service that is not run by root is not the real one: never hand it proxy passwords.
    struct ucred cred;
    socklen_t cl = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl) != 0 || cred.uid != 0) {
        close(fd);
        snprintf(err, errn, "the program listening on %s does not belong to root; refusing to talk to it", path);
        return PBC_REFUSED;
    }
    int rc = handshake(fd, err, errn, running);
    if (rc != PBC_CONNECTED) { close(fd); return rc; }
    *fd_out = fd;
    return PBC_CONNECTED;
}

static const char *socket_path(const char *given)
{
    if (given && *given) return given;
#ifdef PB_TEST_HOOKS
    const char *e = getenv("PROXYBRIDGE_SOCKET");      // the UI test build talks to a service of its own
    if (e && *e) return e;
#endif
    return PB_IPC_SOCKET_PATH;
}

static void start_reader(int fd, bool running)
{
    pthread_mutex_lock(&C.mu);
    C.fd = fd;
    C.alive = true;
    C.service = true;
    C.engine_running = running;
    pthread_mutex_unlock(&C.mu);
    C.reader_started = pthread_create(&C.reader, NULL, reader_main, NULL) == 0;
}

int pbc_connect(const char *path, char *err, size_t errn)
{
    snprintf(C.path, sizeof C.path, "%s", socket_path(path));
    int fd = -1;
    bool running = false;
    int rc = open_connection(C.path, &fd, &running, err, errn);
    if (rc == PBC_CONNECTED) start_reader(fd, running);
    return rc;
}

bool pbc_reconnect(void)
{
    if (!C.service) return false;
    if (C.alive) return true;
    if (C.reader_started) { pthread_join(C.reader, NULL); C.reader_started = false; }
    if (C.fd >= 0) { close(C.fd); C.fd = -1; }
    char err[256];
    int fd = -1;
    bool running = false;
    if (open_connection(C.path, &fd, &running, err, sizeof err) != PBC_CONNECTED) return false;
    start_reader(fd, running);
    return true;
}

void pbc_disconnect(void)
{
    if (!C.service) return;
    if (C.fd >= 0) shutdown(C.fd, SHUT_RDWR);
    if (C.reader_started) { pthread_join(C.reader, NULL); C.reader_started = false; }
    if (C.fd >= 0) { close(C.fd); C.fd = -1; }
    C.alive = false;
}

// ---- one request -----------------------------------------------------------------------------------------------------------
typedef struct {
    bool ok;
    char **f;
    unsigned n;
    char err[256];
} reply_t;

static void reply_free(reply_t *r)
{
    for (unsigned i = 0; i < r->n; i++) g_free(r->f[i]);
    g_free(r->f);
    memset(r, 0, sizeof *r);
}

// line: streamed lines are handed to it on the calling thread, as the library does for the proxy test
static bool rpc(reply_t *r, const char *cmd, unsigned nargs, const char *const *args, void (*line)(const char *, void *), void *user)
{
    memset(r, 0, sizeof *r);
    pthread_mutex_lock(&C.mu);
    if (!C.alive) {
        pthread_mutex_unlock(&C.mu);
        snprintf(r->err, sizeof r->err, "the connection to the ProxyBridge service was lost");
        return false;
    }
    struct pending *p = NULL;
    for (int i = 0; i < MAX_PENDING && !p; i++) if (!C.pend[i].used) p = &C.pend[i];
    if (!p) {
        pthread_mutex_unlock(&C.mu);
        snprintf(r->err, sizeof r->err, "too many requests at once");
        return false;
    }
    memset(p, 0, sizeof *p);
    p->used = true;
    p->lines = g_queue_new();
    int fd = C.fd;                                   // the descriptor this request belongs to; a reconnect gets a new one
    snprintf(p->id, sizeof p->id, "%lu", ++C.next_id);
    char idcopy[24];
    snprintf(idcopy, sizeof idcopy, "%s", p->id);
    pthread_mutex_unlock(&C.mu);

    const char *f[3 + 16];
    unsigned n = 0;
    f[n++] = "q"; f[n++] = idcopy; f[n++] = cmd;
    for (unsigned i = 0; i < nargs && n < 3 + 16; i++) f[n++] = args[i];
    pthread_mutex_lock(&C.send_mu);
    int sent = pb_ipc_send(fd, n, f, NULL);
    pthread_mutex_unlock(&C.send_mu);

    pthread_mutex_lock(&C.mu);
    if (sent != 0) {
        snprintf(r->err, sizeof r->err, "the connection to the ProxyBridge service was lost");
    } else {
        for (;;) {
            while (!g_queue_is_empty(p->lines)) {
                char *l = g_queue_pop_head(p->lines);
                pthread_mutex_unlock(&C.mu);
                if (line) line(l, user);
                g_free(l);
                pthread_mutex_lock(&C.mu);
            }
            if (p->done) break;
            if (!C.alive) {
                snprintf(r->err, sizeof r->err, "the connection to the ProxyBridge service was lost");
                break;
            }
            pthread_cond_wait(&C.cv, &C.mu);
        }
    }
    if (p->done) {
        r->ok = p->ok;
        r->f = p->fields;
        r->n = p->nfields;
        p->fields = NULL;
        p->nfields = 0;
        if (!r->ok) {
            snprintf(r->err, sizeof r->err, "%s", r->n ? r->f[0] : "the ProxyBridge service reported an error");
        }
    }
    free_pending_fields(p);
    g_queue_free_full(p->lines, g_free);
    p->used = false;
    pthread_mutex_unlock(&C.mu);
    return r->ok;
}

static void copy_err(char *dst, size_t n, const reply_t *r)
{
    if (dst && n) snprintf(dst, n, "%s", r->err);
}

static bool simple(const char *cmd, unsigned nargs, const char *const *args)
{
    reply_t r;
    bool ok = rpc(&r, cmd, nargs, args, NULL, NULL);
    reply_free(&r);
    return ok;
}

static bool simple_b(const char *cmd, bool v)
{
    const char *a[] = { v ? "1" : "0" };
    return simple(cmd, 1, a);
}

static uint32_t parse_u32(const char *s)
{
    uint64_t v = 0;
    for (; s && *s >= '0' && *s <= '9' && v < 0xffffffffull; s++) v = v * 10 + (uint64_t)(*s - '0');
    return (uint32_t)v;
}

static bool is_embedded(void) { return !C.service; }

// ---- the engine API --------------------------------------------------------------------------------------------------------
uint32_t pbc_AddProxy(const char *name, ProxyType type, const char *host, uint16_t port, const char *user, const char *pass, char *err, size_t en)
{
    if (is_embedded()) return ProxyBridge_AddProxy(name, type, host, port, user, pass, err, en);
    char t[4], p[8];
    snprintf(t, sizeof t, "%d", (int)type);
    snprintf(p, sizeof p, "%u", port);
    const char *a[] = { name, t, host, p, user ? user : "", pass ? pass : "" };
    reply_t r;
    uint32_t id = 0;
    if (rpc(&r, "proxy.add", 6, a, NULL, NULL) && r.n) id = parse_u32(r.f[0]);
    else copy_err(err, en, &r);
    reply_free(&r);
    return id;
}

bool pbc_EditProxy(uint32_t id, const char *name, ProxyType type, const char *host, uint16_t port, const char *user, const char *pass, char *err, size_t en)
{
    if (is_embedded()) return ProxyBridge_EditProxy(id, name, type, host, port, user, pass, err, en);
    char i[12], t[4], p[8];
    snprintf(i, sizeof i, "%u", id);
    snprintf(t, sizeof t, "%d", (int)type);
    snprintf(p, sizeof p, "%u", port);
    const char *a[] = { i, name, t, host, p, user ? user : "", pass ? pass : "" };
    reply_t r;
    bool ok = rpc(&r, "proxy.edit", 7, a, NULL, NULL);
    if (!ok) copy_err(err, en, &r);
    reply_free(&r);
    return ok;
}

static bool id_cmd(const char *cmd, uint32_t id)
{
    char i[12];
    snprintf(i, sizeof i, "%u", id);
    const char *a[] = { i };
    return simple(cmd, 1, a);
}

bool pbc_SetProxySendDomain(uint32_t id, bool v)
{
    if (is_embedded()) return ProxyBridge_SetProxySendDomain(id, v);
    char i[12];
    snprintf(i, sizeof i, "%u", id);
    const char *a[] = { i, v ? "1" : "0" };
    return simple("proxy.sendDomain", 2, a);
}

bool pbc_DeleteProxy(uint32_t id) { return is_embedded() ? ProxyBridge_DeleteProxy(id) : id_cmd("proxy.delete", id); }
void pbc_ClearProxies(void) { if (is_embedded()) ProxyBridge_ClearProxies(); else simple("proxy.clear", 0, NULL); }
void pbc_SetDefaultProxy(uint32_t id) { if (is_embedded()) ProxyBridge_SetDefaultProxy(id); else id_cmd("proxy.default", id); }

uint32_t pbc_AddRule(const char *proc, const char *hosts, const char *ports, RuleProtocol proto, RuleAction act, uint32_t proxy_id, char *err, size_t en)
{
    if (is_embedded()) return ProxyBridge_AddRule(proc, hosts, ports, proto, act, proxy_id, err, en);
    char pr[4], ac[4], px[12];
    snprintf(pr, sizeof pr, "%d", (int)proto);
    snprintf(ac, sizeof ac, "%d", (int)act);
    snprintf(px, sizeof px, "%u", proxy_id);
    const char *a[] = { proc ? proc : "", hosts ? hosts : "", ports ? ports : "", pr, ac, px };
    reply_t r;
    uint32_t id = 0;
    if (rpc(&r, "rule.add", 6, a, NULL, NULL) && r.n) id = parse_u32(r.f[0]);
    else copy_err(err, en, &r);
    reply_free(&r);
    return id;
}

bool pbc_EditRule(uint32_t id, const char *proc, const char *hosts, const char *ports, RuleProtocol proto, RuleAction act, uint32_t proxy_id, char *err, size_t en)
{
    if (is_embedded()) return ProxyBridge_EditRule(id, proc, hosts, ports, proto, act, proxy_id, err, en);
    char i[12], pr[4], ac[4], px[12];
    snprintf(i, sizeof i, "%u", id);
    snprintf(pr, sizeof pr, "%d", (int)proto);
    snprintf(ac, sizeof ac, "%d", (int)act);
    snprintf(px, sizeof px, "%u", proxy_id);
    const char *a[] = { i, proc ? proc : "", hosts ? hosts : "", ports ? ports : "", pr, ac, px };
    reply_t r;
    bool ok = rpc(&r, "rule.edit", 7, a, NULL, NULL);
    if (!ok) copy_err(err, en, &r);
    reply_free(&r);
    return ok;
}

bool pbc_SetRuleLocalhost(uint32_t id, bool on)
{
    if (is_embedded()) return ProxyBridge_SetRuleLocalhost(id, on);
    char i[12];
    snprintf(i, sizeof i, "%u", id);
    const char *a[] = { i, on ? "1" : "0" };
    return simple("rule.localhost", 2, a);
}

bool pbc_EnableRule(uint32_t id) { return is_embedded() ? ProxyBridge_EnableRule(id) : id_cmd("rule.enable", id); }
bool pbc_DisableRule(uint32_t id) { return is_embedded() ? ProxyBridge_DisableRule(id) : id_cmd("rule.disable", id); }
bool pbc_DeleteRule(uint32_t id) { return is_embedded() ? ProxyBridge_DeleteRule(id) : id_cmd("rule.delete", id); }

bool pbc_MoveRule(uint32_t id, int index)
{
    if (is_embedded()) return ProxyBridge_MoveRule(id, index);
    char i[12], x[12];
    snprintf(i, sizeof i, "%u", id);
    snprintf(x, sizeof x, "%d", index < 0 ? 0 : index);
    const char *a[] = { i, x };
    return simple("rule.move", 2, a);
}

void pbc_ClearRules(void) { if (is_embedded()) ProxyBridge_ClearRules(); else simple("rule.clear", 0, NULL); }

bool pbc_ValidateRule(const char *proc, const char *hosts, const char *ports, char *err, size_t en)
{
    if (is_embedded()) return ProxyBridge_ValidateRule(proc, hosts, ports, err, en);
    const char *a[] = { proc ? proc : "", hosts ? hosts : "", ports ? ports : "" };
    reply_t r;
    bool ok = rpc(&r, "rule.validate", 3, a, NULL, NULL);
    if (!ok) copy_err(err, en, &r);
    reply_free(&r);
    return ok;
}

void pbc_SetDnsViaProxy(bool v) { if (is_embedded()) ProxyBridge_SetDnsViaProxy(v); else simple_b("cfg.dns", v); }
void pbc_SetEnabled(bool v) { if (is_embedded()) ProxyBridge_SetEnabled(v); else simple_b("cfg.enabled", v); }
void pbc_SetLogEveryConnection(bool v) { if (is_embedded()) ProxyBridge_SetLogEveryConnection(v); else simple_b("cfg.logEvery", v); }
void pbc_SetTrafficLoggingEnabled(bool v) { if (is_embedded()) ProxyBridge_SetTrafficLoggingEnabled(v); else simple_b("cfg.logging", v); }
void pbc_BeginBatch(void) { if (is_embedded()) ProxyBridge_BeginBatch(); else simple("batch.begin", 0, NULL); }
void pbc_EndBatch(void) { if (is_embedded()) ProxyBridge_EndBatch(); else simple("batch.end", 0, NULL); }

void pbc_SetLogCallback(LogCallback cb)
{
    pthread_mutex_lock(&C.mu);
    C.log_cb = cb;
    pthread_mutex_unlock(&C.mu);
    if (is_embedded()) ProxyBridge_SetLogCallback(cb);
}

void pbc_SetConnectionCallbackEx(ConnectionCallbackEx cb)
{
    pthread_mutex_lock(&C.mu);
    C.conn_cb = cb;
    pthread_mutex_unlock(&C.mu);
    if (is_embedded()) ProxyBridge_SetConnectionCallbackEx(cb);
}

bool pbc_Start(void)
{
    if (is_embedded()) return ProxyBridge_Start();
    return simple("engine.start", 0, NULL);
}

bool pbc_Stop(void)
{
    if (is_embedded()) return ProxyBridge_Stop();
    return simple("engine.stop", 0, NULL);
}

static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : 0; }

uint32_t pbc_GetFlows(ProxyBridgeFlow *out, uint32_t max)
{
    if (is_embedded()) return ProxyBridge_GetFlows(out, max);
    reply_t r;
    uint32_t n = 0;
    if (rpc(&r, "flows.get", 0, NULL, NULL, NULL)) {
        for (unsigned i = 0; i < r.n && n < max && n < PB_FLOWS_MAX; i++) {
            gchar **t = g_strsplit(r.f[i], "\t", 12);
            if (g_strv_length(t) == 12) {
                ProxyBridgeFlow *o = &out[n];
                memset(o, 0, sizeof *o);
                o->id = g_ascii_strtoull(t[0], NULL, 10);
                o->pid = parse_u32(t[1]);
                o->proxy_id = parse_u32(t[2]);
                o->age_ms = parse_u32(t[3]);
                o->sent = g_ascii_strtoull(t[4], NULL, 10);
                o->received = g_ascii_strtoull(t[5], NULL, 10);
                o->port = (uint16_t)parse_u32(t[6]);
                o->is_udp = (uint8_t)parse_u32(t[7]);
                o->is_ipv6 = (uint8_t)parse_u32(t[8]);
                if (strlen(t[9]) == 32) for (int k = 0; k < 16; k++) o->dest[k] = (uint8_t)(hexv(t[9][2 * k]) * 16 + hexv(t[9][2 * k + 1]));
                snprintf(o->name, sizeof o->name, "%s", t[10]);
                snprintf(o->host, sizeof o->host, "%s", t[11]);
                n++;
            }
            g_strfreev(t);
        }
    }
    reply_free(&r);
    return n;
}

int pbc_TestProxyEx(uint32_t proxy_id, const char *host, uint16_t port, ProxyTestLogCallback cb, void *user)
{
    if (is_embedded()) return ProxyBridge_TestProxyEx(proxy_id, host, port, cb, user);
    char i[12], p[8];
    snprintf(i, sizeof i, "%u", proxy_id);
    snprintf(p, sizeof p, "%u", port);
    const char *a[] = { i, host, p };
    reply_t r;
    int rc = -1;
    if (rpc(&r, "proxy.test", 3, a, (void (*)(const char *, void *))cb, user) && r.n) {
        rc = (int)parse_long(r.f[0]);
    } else if (cb) {
        cb(r.err, user);
    }
    reply_free(&r);
    return rc;
}

void pbc_replay_history(LogCallback cb)
{
    if (is_embedded() || !cb) return;
    reply_t r;
    if (rpc(&r, "log.history", 0, NULL, NULL, NULL))
        for (unsigned i = 0; i < r.n; i++) cb(r.f[i]);
    reply_free(&r);
}

// ---- boot ------------------------------------------------------------------------------------------------------------------
bool pbc_boot_is_enabled(void)
{
    if (is_embedded()) return boot_is_enabled();
    return g_chk_boot;                     // read from the service's settings when the window started
}

bool pbc_boot_set(bool enable, char **error)
{
    if (error) *error = NULL;
    if (is_embedded()) return boot_set(enable, error);
    const char *a[] = { enable ? "1" : "0" };
    reply_t r;
    bool ok = rpc(&r, "boot.set", 1, a, NULL, NULL);
    if (!ok && error) *error = g_strdup(r.err);
    reply_free(&r);
    return ok;
}

// ---- profile store ---------------------------------------------------------------------------------------------------------
static bool st_list(GPtrArray *names)
{
    reply_t r;
    bool ok = rpc(&r, "store.list", 0, NULL, NULL, NULL);
    if (ok) for (unsigned i = 0; i < r.n; i++) g_ptr_array_add(names, g_strdup(r.f[i]));
    reply_free(&r);
    return ok;
}

static char *st_get(const char *name)
{
    const char *a[] = { name };
    reply_t r;
    char *out = NULL;
    if (rpc(&r, "store.get", 1, a, NULL, NULL) && r.n) out = g_strdup(r.f[0]);
    reply_free(&r);
    return out;
}

static bool st_put(const char *name, const char *data, char *err, size_t en)
{
    const char *a[] = { name, data };
    reply_t r;
    bool ok = rpc(&r, "store.put", 2, a, NULL, NULL);
    if (!ok) copy_err(err, en, &r);
    reply_free(&r);
    return ok;
}

static bool st_del(const char *name)
{
    const char *a[] = { name };
    return simple("store.delete", 1, a);
}

static bool st_settings_get(char **active, bool *updates, bool *boot)
{
    reply_t r;
    bool ok = rpc(&r, "store.settings.get", 0, NULL, NULL, NULL) && r.n >= 3;
    if (ok) {
        *active = r.f[0][0] ? g_strdup(r.f[0]) : NULL;
        *updates = r.f[1][0] == '1';
        *boot = r.f[2][0] == '1';
    }
    reply_free(&r);
    return ok;
}

static bool st_settings_set(const char *active, bool updates, bool boot, char *err, size_t en)
{
    const char *a[] = { active ? active : "", updates ? "1" : "0", boot ? "1" : "0" };
    reply_t r;
    bool ok = rpc(&r, "store.settings.set", 3, a, NULL, NULL);
    if (!ok) copy_err(err, en, &r);
    reply_free(&r);
    return ok;
}

static bool st_exists(const char *name) { (void)name; return true; }     // the service owns the files; nothing can delete them behind our back

static char *st_legacy_get(void)
{
    reply_t r;
    char *out = NULL;
    if (rpc(&r, "store.legacy", 0, NULL, NULL, NULL) && r.n) out = g_strdup(r.f[0]);
    reply_free(&r);
    return out;
}

static void st_legacy_done(void) { simple("store.legacy_done", 0, NULL); }

const struct gui_store pbc_store = { st_list, st_get, st_put, st_del, st_exists, st_settings_get, st_settings_set, st_legacy_get, st_legacy_done };

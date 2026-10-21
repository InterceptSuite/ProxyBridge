#define _GNU_SOURCE
#include "daemon.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#include "../src/ProxyBridge.h"
#include "../src/pb_ipc.h"
#include "../profile/pb_profile.h"

#define GROUP_NAME      "proxybridge"
#define MAX_CLIENTS     16
#define MAX_PROFILES    512
#define EVENT_QUEUE_MAX 20000
#define QUEUE_BYTES_MAX (64u << 20)     // what one window may have waiting to be read before it is cut off
#define BODY_TIMEOUT_MS 30000           // a frame whose header arrived must follow within this
#define BATCH_MAX_MS    10000           // a window may hold the kernel update back this long
#define RECHECK_S       5               // how often an open connection is checked against the group again
#define STORE_MAX_BYTES (256u << 20)    // all profile files together
#define HISTORY_LINES   200

// ---- clients ---------------------------------------------------------------------------------------------------------------
struct outmsg {
    struct outmsg *next;
    unsigned char *frame;
    size_t len;
    bool event;
};

struct client {
    int fd;
    uid_t uid;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct outmsg *head, *tail;
    size_t nevents;                 // queued events (dropped when too many are waiting)
    size_t qbytes;                  // bytes queued; responses are never dropped, a window that lets them pile up is disconnected
    unsigned long dropped;          // events dropped since the window last caught up
    bool closing;
    int batch_depth;                // BeginBatch calls this client has not yet closed
    int64_t batch_t0;               // when the first of them was made (ms, monotonic)
    time_t last_check;              // last time uid_allowed() was asked for this connection
    atomic_int refs;
    struct client *next;
};

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static pthread_mutex_t clients_mu = PTHREAD_MUTEX_INITIALIZER;
static struct client *clients;
static int nclients;
static int verbose;

// engine state as the daemon last set it (the library has no getters)
static pthread_mutex_t state_mu = PTHREAD_MUTEX_INITIALIZER;
static bool engine_running;
static bool engine_enabled = true;
static bool logging_requested;

static char history[HISTORY_LINES][512];
static unsigned history_count;      // total lines ever written
static pthread_mutex_t history_mu = PTHREAD_MUTEX_INITIALIZER;

static void enqueue(struct client *c, unsigned char *frame, size_t len, bool is_event)
{
    pthread_mutex_lock(&c->mu);
    if (c->closing || (is_event && c->nevents >= EVENT_QUEUE_MAX)) {
        if (is_event && !c->closing) c->dropped++;
        pthread_mutex_unlock(&c->mu);
        free(frame);
        return;
    }
    if (c->qbytes + len > QUEUE_BYTES_MAX) {
        // A window that asks for things and does not read the answers would make the service hold them all: cut it off.
        if (!is_event) { c->closing = true; pthread_cond_signal(&c->cv); }
        else c->dropped++;
        pthread_mutex_unlock(&c->mu);
        if (!is_event) shutdown(c->fd, SHUT_RDWR);
        free(frame);
        return;
    }
    struct outmsg *m = malloc(sizeof *m);
    if (!m) { pthread_mutex_unlock(&c->mu); free(frame); return; }
    m->next = NULL; m->frame = frame; m->len = len; m->event = is_event;
    if (c->tail) c->tail->next = m; else c->head = m;
    c->tail = m;
    c->qbytes += len;
    if (is_event) c->nevents++;
    pthread_cond_signal(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static void send_to(struct client *c, bool is_event, unsigned n, const char *const *f)
{
    size_t len;
    unsigned char *frame = pb_ipc_encode(n, f, NULL, &len);
    if (frame) enqueue(c, frame, len, is_event);
}

static void broadcast(unsigned n, const char *const *f)
{
    size_t len;
    unsigned char *frame = pb_ipc_encode(n, f, NULL, &len);
    if (!frame) return;
    pthread_mutex_lock(&clients_mu);
    for (struct client *c = clients; c; c = c->next) {
        unsigned char *copy = malloc(len);
        if (!copy) continue;
        memcpy(copy, frame, len);
        enqueue(c, copy, len, true);
    }
    pthread_mutex_unlock(&clients_mu);
    free(frame);
}

static void *writer_main(void *arg)
{
    struct client *c = arg;
    for (;;) {
        pthread_mutex_lock(&c->mu);
        while (!c->head && !c->closing) pthread_cond_wait(&c->cv, &c->mu);
        if (c->closing) { pthread_mutex_unlock(&c->mu); break; }
        struct outmsg *m = c->head;
        c->head = m->next;
        if (!c->head) c->tail = NULL;
        c->qbytes -= m->len;
        if (m->event) c->nevents--;                  // the budget is for what is waiting, not for the life of the connection
        unsigned long lost = 0;
        if (!c->head && c->dropped) { lost = c->dropped; c->dropped = 0; }
        pthread_mutex_unlock(&c->mu);
        size_t off = 0;
        bool ok = true;
        while (off < m->len) {
            ssize_t w = send(c->fd, m->frame + off, m->len - off, MSG_NOSIGNAL);
            if (w > 0) { off += (size_t)w; continue; }
            if (w < 0 && errno == EINTR) continue;
            ok = false;
            break;
        }
        free(m->frame);
        free(m);
        if (ok && lost) {                            // tell the window it missed something instead of letting it assume it saw everything
            char note[96];
            snprintf(note, sizeof note, "%lu connection or log events were dropped because this window was too slow", lost);
            const char *nf[] = { "e", "log", note };
            size_t nl;
            unsigned char *nfr = pb_ipc_encode(3, nf, NULL, &nl);
            if (nfr) { ok = send(c->fd, nfr, nl, MSG_NOSIGNAL) == (ssize_t)nl; free(nfr); }
        }
        if (!ok) {
            pthread_mutex_lock(&c->mu);
            c->closing = true;
            pthread_mutex_unlock(&c->mu);
            shutdown(c->fd, SHUT_RDWR);          // wakes the reader
            break;
        }
    }
    if (atomic_fetch_sub(&c->refs, 1) == 1) {
        for (struct outmsg *m = c->head; m;) { struct outmsg *n = m->next; free(m->frame); free(m); m = n; }
        close(c->fd);
        pthread_mutex_destroy(&c->mu);
        pthread_cond_destroy(&c->cv);
        free(c);
    }
    return NULL;
}

// ---- logging ---------------------------------------------------------------------------------------------------------------
static void on_log(const char *msg)
{
    pthread_mutex_lock(&history_mu);
    snprintf(history[history_count % HISTORY_LINES], sizeof history[0], "%s", msg);
    history_count++;
    pthread_mutex_unlock(&history_mu);
    if (verbose == 1 || verbose == 3) { printf("[LOG] %s\n", msg); fflush(stdout); }
    const char *f[] = { "e", "log", msg };
    broadcast(3, f);
}

static void dlog(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void dlog(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    for (char *p = buf; *p; p++) if ((unsigned char)*p < 0x20 || *p == 0x7f) *p = '?';
    // the daemon's own lines go to the journal always: a service nobody watches still has to say why it did something
    printf("[PB] %s\n", buf);
    fflush(stdout);
    pthread_mutex_lock(&history_mu);
    snprintf(history[history_count % HISTORY_LINES], sizeof history[0], "%s", buf);
    history_count++;
    pthread_mutex_unlock(&history_mu);
    const char *f[] = { "e", "log", buf };
    broadcast(3, f);
}

static void on_conn(const char *proc, uint32_t pid, const char *ip, uint16_t port, const char *proto, const char *via)
{
    char pidb[16], portb[8];
    snprintf(pidb, sizeof pidb, "%u", pid);
    snprintf(portb, sizeof portb, "%u", port);
    if (verbose == 2 || verbose == 3) {
        printf("[CONN] %s (PID:%u) -> %s:%u via %s%s\n", proc, pid, ip, port, via, proto && !strcmp(proto, "UDP") ? " (UDP)" : "");
        fflush(stdout);
    }
    const char *f[] = { "e", "conn", proc, pidb, ip, portb, proto ? proto : "TCP", via };
    broadcast(8, f);
}

// ---- helpers ---------------------------------------------------------------------------------------------------------------
// Numbers are parsed here, not with strto*, so the program does not depend on the C library's redirected symbols.
static bool pu(const char *s, uint64_t max, uint64_t *out)
{
    if (!s || !*s || strlen(s) > 19) return false;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        v = v * 10 + (uint64_t)(*p - '0');
    }
    if (v > max) return false;
    *out = v;
    return true;
}

static void reply(struct client *c, const char *id, const char *status, unsigned nextra, const char *const *extra)
{
    const char *f[8 + 4];
    unsigned n = 0;
    f[n++] = "r"; f[n++] = id; f[n++] = status;
    for (unsigned i = 0; i < nextra && n < 12; i++) f[n++] = extra[i];
    send_to(c, false, n, f);
}

static void reply_ok(struct client *c, const char *id) { reply(c, id, "ok", 0, NULL); }
static void reply_ok1(struct client *c, const char *id, const char *v) { const char *x[] = { v }; reply(c, id, "ok", 1, x); }
static void reply_err(struct client *c, const char *id, const char *why) { const char *x[] = { why }; reply(c, id, "err", 1, x); }

static void reply_u64(struct client *c, const char *id, uint64_t v)
{
    char b[24];
    snprintf(b, sizeof b, "%llu", (unsigned long long)v);
    reply_ok1(c, id, b);
}

// ---- profile store ---------------------------------------------------------------------------------------------------------
static bool ensure_dir(const char *dir)
{
    struct stat st;
    if (stat(dir, &st) == -1) {
        if (mkdir(dir, 0700) != 0 && errno != EEXIST) return false;
    } else if (chmod(dir, 0700) != 0) {
        return false;
    }
    return true;
}

static bool ensure_store(void)
{
    char sub[4096];
    snprintf(sub, sizeof sub, "%s/profiles", pbp_config_dir());
    return ensure_dir(pbp_config_dir()) && ensure_dir(sub);
}

// Profile names: stored encoded, so any name is safe on disk, but a name with control characters would reach menus, window titles and
// logs of every user of the window. Rejected for new profiles.
static bool name_ok(const char *name)
{
    if (!name || !*name || strlen(name) > 200) return false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++)
        if (*p < 0x20 || *p == 0x7f) return false;
    return true;
}

static char *profile_file(const char *name)
{
    char *file = pbp_filename_for(name);
    if (!file) return NULL;
    char *path = NULL;
    if (asprintf(&path, "%s/profiles/%s", pbp_config_dir(), file) < 0) path = NULL;
    free(file);
    return path;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void store_list(struct client *c, const char *id)
{
    char dir[4096];
    snprintf(dir, sizeof dir, "%s/profiles", pbp_config_dir());
    DIR *d = opendir(dir);
    char **names = calloc(MAX_PROFILES + 1, sizeof *names);
    unsigned n = 0;
    struct dirent *de;
    while (names && d && (de = readdir(d)) != NULL && n < MAX_PROFILES) {
        char *name = pbp_name_from_filename(de->d_name);
        if (name) names[n++] = name;
    }
    if (d) closedir(d);
    if (!names) { reply_err(c, id, "out of memory"); return; }
    qsort(names, n, sizeof *names, cmp_str);
    const char **f = calloc(n + 3, sizeof *f);
    if (f) {
        f[0] = "r"; f[1] = id; f[2] = "ok";
        for (unsigned i = 0; i < n; i++) f[3 + i] = names[i];
        send_to(c, false, n + 3, f);
        free(f);
    }
    for (unsigned i = 0; i < n; i++) free(names[i]);
    free(names);
}

static void store_get(struct client *c, const char *id, const char *name)
{
    char *path = profile_file(name);
    if (!path) { reply_err(c, id, "unusable profile name"); return; }
    FILE *f = fopen(path, "rb");
    free(path);
    if (!f) { reply_err(c, id, "no such profile"); return; }
    char *buf = malloc(PBP_MAX_FILE + 1);
    size_t n = buf ? fread(buf, 1, PBP_MAX_FILE + 1, f) : 0;
    fclose(f);
    if (!buf || n > PBP_MAX_FILE) { free(buf); reply_err(c, id, "profile file too large"); return; }
    buf[n] = '\0';
    const char *fl[] = { "r", id, "ok", buf };
    size_t ll[] = { 1, strlen(id), 2, n };
    size_t len;
    unsigned char *frame = pb_ipc_encode(4, fl, ll, &len);
    if (frame) enqueue(c, frame, len, false); else reply_err(c, id, "profile file too large");
    free(buf);
}

static unsigned long long store_bytes(void)
{
    char dir[4096];
    snprintf(dir, sizeof dir, "%s/profiles", pbp_config_dir());
    DIR *d = opendir(dir);
    unsigned long long total = 0;
    struct dirent *de;
    while (d && (de = readdir(d)) != NULL) {
        char path[4400];
        struct stat st;
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        if (lstat(path, &st) == 0 && S_ISREG(st.st_mode)) total += (unsigned long long)st.st_size;
    }
    if (d) closedir(d);
    return total;
}

// A crash in the middle of a write leaves "<file>.tmp.XXXXXX"; nothing else ever removes them
static void sweep_temp_files(void)
{
    char dir[4096];
    snprintf(dir, sizeof dir, "%s/profiles", pbp_config_dir());
    DIR *d = opendir(dir);
    struct dirent *de;
    while (d && (de = readdir(d)) != NULL) {
        if (!strstr(de->d_name, ".tmp.")) continue;
        char path[4400];
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        unlink(path);
    }
    if (d) closedir(d);
    d = opendir(pbp_config_dir());                 // the same for a settings.json that was being replaced
    while (d && (de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "settings.json.tmp.", 17) != 0) continue;
        char path[4400];
        snprintf(path, sizeof path, "%s/%s", pbp_config_dir(), de->d_name);
        unlink(path);
    }
    if (d) closedir(d);
}

static void store_put(struct client *c, const char *id, const char *name, const char *data, size_t dlen)
{
    if (dlen > PBP_MAX_FILE) { reply_err(c, id, "profile too large"); return; }
    if (!name_ok(name)) { reply_err(c, id, "unusable profile name (empty, over 200 bytes, or with control characters)"); return; }
    char *path = profile_file(name);
    if (!path) { reply_err(c, id, "unusable profile name"); return; }
    struct pbp_profile p;
    char err[256];
    if (pbp_parse(data, dlen, &p, err, sizeof err) != 0) { free(path); reply_err(c, id, err); return; }
    pbp_free(&p);
    if (access(path, F_OK) != 0) {                 // a new profile: keep the number bounded
        char dir[4096];
        snprintf(dir, sizeof dir, "%s/profiles", pbp_config_dir());
        unsigned count = 0;
        DIR *d = opendir(dir);
        struct dirent *de;
        while (d && (de = readdir(d)) != NULL) { char *nm = pbp_name_from_filename(de->d_name); if (nm) count++; free(nm); }
        if (d) closedir(d);
        if (count >= MAX_PROFILES) { free(path); reply_err(c, id, "too many profiles"); return; }
    }
    if (!ensure_store()) { free(path); reply_err(c, id, "cannot create the configuration folder"); return; }
    if (store_bytes() + dlen > STORE_MAX_BYTES) { free(path); reply_err(c, id, "the profile store is full"); return; }
    if (pbp_write_file(path, data, err, sizeof err) != 0) { free(path); reply_err(c, id, err); return; }
    free(path);
    reply_ok(c, id);
}

static void store_delete(struct client *c, const char *id, const char *name)
{
    char *path = profile_file(name);
    if (!path) { reply_err(c, id, "unusable profile name"); return; }
    int rc = unlink(path);
    free(path);
    if (rc != 0 && errno != ENOENT) reply_err(c, id, strerror(errno)); else reply_ok(c, id);
}

// ---- engine control --------------------------------------------------------------------------------------------------------
static pthread_mutex_t engine_mu = PTHREAD_MUTEX_INITIALIZER;     // one start or stop at a time, whoever asks

static bool engine_start(void)
{
    pthread_mutex_lock(&engine_mu);
    bool ok = ProxyBridge_Start();
    pthread_mutex_lock(&state_mu);
    engine_running = ok;
    pthread_mutex_unlock(&state_mu);
    pthread_mutex_unlock(&engine_mu);
    return ok;
}

static void engine_stop(void)
{
    pthread_mutex_lock(&engine_mu);
    ProxyBridge_Stop();
    pthread_mutex_lock(&state_mu);
    engine_running = false;
    pthread_mutex_unlock(&state_mu);
    pthread_mutex_unlock(&engine_mu);
}

static void update_logging(void)
{
    pthread_mutex_lock(&clients_mu);
    int n = nclients;
    pthread_mutex_unlock(&clients_mu);
    pthread_mutex_lock(&state_mu);                // decided and applied under one lock, so two threads cannot apply stale values
    bool on = logging_requested && n > 0;
    ProxyBridge_SetTrafficLoggingEnabled(on || verbose == 2 || verbose == 3);
    pthread_mutex_unlock(&state_mu);
}

// Loads the profile that was active when the service last ran, so the machine is routed from the moment it boots, before any
// window is opened.
static void apply_active_profile(void)
{
    char *active = NULL;
    char path[4096];
    snprintf(path, sizeof path, "%s/settings.json", pbp_config_dir());
    if (pbp_settings_load(path, &active, NULL, NULL) != 0 || !active || !*active) {
        free(active);
        dlog("no active profile yet: waiting for a window to set one up");
        return;
    }
    char *file = profile_file(active);
    struct pbp_profile prof;
    char err[256];
    if (!file || pbp_load_file(file, &prof, err, sizeof err) != 0) {
        dlog("profile '%s' cannot be loaded: %s", active, file ? err : "unusable name");
        free(file);
        free(active);
        return;
    }
    free(file);

    ProxyBridge_BeginBatch();
    ProxyBridge_ClearRules();
    ProxyBridge_ClearProxies();
    ProxyBridge_SetDnsViaProxy(prof.dns_via_proxy);
    ProxyBridge_SetLogEveryConnection(prof.log_every);
    uint32_t ids[PBP_MAX_PROXIES + 1] = { 0 };
    bool ok = true;
    for (size_t i = 0; i < prof.nproxies && ok; i++) {
        const struct pbp_proxy *p = &prof.proxies[i];
        ids[i] = ProxyBridge_AddProxy(p->name, p->type ? PROXY_TYPE_SOCKS5 : PROXY_TYPE_HTTP, p->host, p->port, p->user, p->pass, err, sizeof err);
        if (!ids[i]) { dlog("profile '%s': proxy '%s': %s", active, p->name, err); ok = false; break; }
        if (!p->send_domain) ProxyBridge_SetProxySendDomain(ids[i], false);
    }
    if (ok && prof.default_proxy_id)
        for (size_t i = 0; i < prof.nproxies; i++)
            if (prof.proxies[i].id == prof.default_proxy_id) ProxyBridge_SetDefaultProxy(ids[i]);
    size_t enabled = 0;
    for (size_t i = 0; i < prof.nrules && ok; i++) {
        const struct pbp_rule *r = &prof.rules[i];
        if (!r->enabled) continue;
        uint32_t proxy_id = 0;
        if (r->action == RULE_ACTION_PROXY && r->proxy_id)
            for (size_t k = 0; k < prof.nproxies; k++)
                if (prof.proxies[k].id == r->proxy_id) proxy_id = ids[k];
        uint32_t rid = ProxyBridge_AddRule(r->process, r->hosts, r->ports, (RuleProtocol)r->protocol, (RuleAction)r->action, proxy_id, err, sizeof err);
        if (!rid) { dlog("profile '%s': rule %zu: %s", active, i + 1, err); ok = false; break; }
        if (r->localhost && r->action == RULE_ACTION_PROXY) ProxyBridge_SetRuleLocalhost(rid, true);
        enabled++;
    }
    ProxyBridge_EndBatch();
    if (!ok) {
        ProxyBridge_ClearRules();
        ProxyBridge_ClearProxies();
    } else {
        dlog("profile '%s' loaded: %zu proxies, %zu rules", active, prof.nproxies, enabled);
    }
    pbp_free(&prof);
    free(active);
}

// ---- requests --------------------------------------------------------------------------------------------------------------
struct test_ctx { struct client *c; const char *id; };
static pthread_mutex_t test_mu = PTHREAD_MUTEX_INITIALIZER;

static void test_line(const char *line, void *user)
{
    struct test_ctx *t = user;
    const char *f[] = { "r", t->id, "line", line };
    send_to(t->c, false, 4, f);
}

#define NEED(cnt) do { if (m->n != (unsigned)(cnt) + 3) { reply_err(c, id, "wrong number of arguments"); return; } } while (0)
#define ARG(i) (m->f[3 + (i)])

static bool bool_arg(const char *s, bool *out)
{
    if (!strcmp(s, "0")) { *out = false; return true; }
    if (!strcmp(s, "1")) { *out = true; return true; }
    return false;
}

static int read_settings(char **active, bool *updates, bool *boot)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/settings.json", pbp_config_dir());
    return pbp_settings_load(path, active, updates, boot);
}

static int write_settings(const char *active, bool updates, bool boot, char *err, size_t errn)
{
    char path[4096];
    if (!ensure_store()) { snprintf(err, errn, "cannot create the configuration folder"); return -1; }
    snprintf(path, sizeof path, "%s/settings.json", pbp_config_dir());
    return pbp_settings_save(path, active, updates, boot, err, errn);
}

static void handle(struct client *c, pb_msg *m)
{
    if (m->n < 3 || strcmp(m->f[0], "q") != 0) return;
    const char *id = m->f[1], *cmd = m->f[2];
    if (m->len[1] > 24) {                           // an id is a short counter; anything else is not a window of ours
        pthread_mutex_lock(&c->mu); c->closing = true; pthread_cond_signal(&c->cv); pthread_mutex_unlock(&c->mu);
        shutdown(c->fd, SHUT_RDWR);
        return;
    }
    char err[256] = "";
    uint64_t a, b;
    bool on;

    if (!strcmp(cmd, "hello")) {
        NEED(1);
        if (!pu(ARG(0), 1000, &a) || a != PB_IPC_PROTOCOL) {
            snprintf(err, sizeof err, "protocol mismatch: the service speaks %d; update or restart ProxyBridge so both are the same version", PB_IPC_PROTOCOL);
            reply_err(c, id, err);
            return;
        }
        pthread_mutex_lock(&state_mu);
        const char *x[] = { PROXYBRIDGE_VERSION, engine_running ? "1" : "0", engine_enabled ? "1" : "0" };
        pthread_mutex_unlock(&state_mu);
        reply(c, id, "ok", 3, x);
    } else if (!strcmp(cmd, "log.history")) {
        NEED(0);
        pthread_mutex_lock(&history_mu);
        unsigned total = history_count < HISTORY_LINES ? history_count : HISTORY_LINES;
        const char **f = calloc(total + 3, sizeof *f);
        char (*copy)[512] = malloc(total ? total * sizeof *copy : 1);
        if (f && copy) {
            for (unsigned i = 0; i < total; i++) {
                unsigned idx = (history_count - total + i) % HISTORY_LINES;
                memcpy(copy[i], history[idx], sizeof copy[i]);
                f[3 + i] = copy[i];
            }
        }
        pthread_mutex_unlock(&history_mu);
        if (f && copy) { f[0] = "r"; f[1] = id; f[2] = "ok"; send_to(c, false, total + 3, f); }
        else reply_err(c, id, "out of memory");
        free(f); free(copy);
    }
    // ---- proxies
    else if (!strcmp(cmd, "proxy.add") || !strcmp(cmd, "proxy.edit")) {
        bool edit = cmd[6] == 'e';
        unsigned base = edit ? 1 : 0;
        NEED(6 + base);
        uint64_t pid = 0, type, port;
        if (edit && !pu(ARG(0), 0xffffffffu, &pid)) { reply_err(c, id, "bad proxy id"); return; }
        if (!pu(ARG(base + 1), 1, &type) || !pu(ARG(base + 3), 65535, &port)) { reply_err(c, id, "bad proxy type or port"); return; }
        if (edit) {
            if (!ProxyBridge_EditProxy((uint32_t)pid, ARG(base), (ProxyType)type, ARG(base + 2), (uint16_t)port, ARG(base + 4), ARG(base + 5), err, sizeof err))
                reply_err(c, id, err[0] ? err : "unknown proxy");
            else reply_u64(c, id, pid);
        } else {
            uint32_t nid = ProxyBridge_AddProxy(ARG(base), (ProxyType)type, ARG(base + 2), (uint16_t)port, ARG(base + 4), ARG(base + 5), err, sizeof err);
            if (!nid) reply_err(c, id, err[0] ? err : "proxy rejected"); else reply_u64(c, id, nid);
        }
    } else if (!strcmp(cmd, "proxy.sendDomain")) {
        NEED(2);
        if (!pu(ARG(0), 0xffffffffu, &a) || !bool_arg(ARG(1), &on)) { reply_err(c, id, "bad arguments"); return; }
        if (ProxyBridge_SetProxySendDomain((uint32_t)a, on)) reply_ok(c, id); else reply_err(c, id, "unknown proxy");
    } else if (!strcmp(cmd, "proxy.delete")) {
        NEED(1);
        if (!pu(ARG(0), 0xffffffffu, &a)) { reply_err(c, id, "bad proxy id"); return; }
        if (ProxyBridge_DeleteProxy((uint32_t)a)) reply_ok(c, id); else reply_err(c, id, "unknown proxy");
    } else if (!strcmp(cmd, "proxy.clear")) {
        NEED(0);
        ProxyBridge_ClearProxies();
        reply_ok(c, id);
    } else if (!strcmp(cmd, "proxy.default")) {
        NEED(1);
        if (!pu(ARG(0), 0xffffffffu, &a)) { reply_err(c, id, "bad proxy id"); return; }
        ProxyBridge_SetDefaultProxy((uint32_t)a);
        reply_ok(c, id);
    } else if (!strcmp(cmd, "proxy.test")) {
        NEED(3);
        if (!pu(ARG(0), 0xffffffffu, &a) || !pu(ARG(2), 65535, &b)) { reply_err(c, id, "bad arguments"); return; }
        size_t hl = strlen(ARG(1));
        bool host_ok = hl > 0 && hl <= 253;
        for (const unsigned char *p = (const unsigned char *)ARG(1); host_ok && *p; p++) if (*p <= 0x20 || *p >= 0x7f) host_ok = false;
        if (!host_ok) { reply_err(c, id, "the target host must be 1 to 253 printable characters without spaces"); return; }
        // The test makes this root service open connections. One at a time keeps a window from tying up the name-resolver threads
        // that the relay needs for the proxies' own host names.
        if (pthread_mutex_trylock(&test_mu) != 0) { reply_err(c, id, "another proxy test is already running"); return; }
        struct test_ctx t = { c, id };
        int rc = ProxyBridge_TestProxyEx((uint32_t)a, ARG(1), (uint16_t)b, test_line, &t);
        pthread_mutex_unlock(&test_mu);
        char r[16];
        snprintf(r, sizeof r, "%d", rc);
        reply_ok1(c, id, r);
    }
    // ---- rules
    else if (!strcmp(cmd, "rule.add") || !strcmp(cmd, "rule.edit")) {
        bool edit = cmd[5] == 'e';
        unsigned base = edit ? 1 : 0;
        NEED(6 + base);
        uint64_t rid = 0, proto, action, pid;
        if (edit && !pu(ARG(0), 0xffffffffu, &rid)) { reply_err(c, id, "bad rule id"); return; }
        if (!pu(ARG(base + 3), 2, &proto) || !pu(ARG(base + 4), 2, &action) || !pu(ARG(base + 5), 0xffffffffu, &pid)) { reply_err(c, id, "bad protocol, action or proxy"); return; }
        if (edit) {
            if (!ProxyBridge_EditRule((uint32_t)rid, ARG(base), ARG(base + 1), ARG(base + 2), (RuleProtocol)proto, (RuleAction)action, (uint32_t)pid, err, sizeof err))
                reply_err(c, id, err[0] ? err : "unknown rule");
            else reply_u64(c, id, rid);
        } else {
            uint32_t nid = ProxyBridge_AddRule(ARG(base), ARG(base + 1), ARG(base + 2), (RuleProtocol)proto, (RuleAction)action, (uint32_t)pid, err, sizeof err);
            if (!nid) reply_err(c, id, err[0] ? err : "rule rejected"); else reply_u64(c, id, nid);
        }
    } else if (!strcmp(cmd, "rule.validate")) {
        NEED(3);
        if (ProxyBridge_ValidateRule(ARG(0), ARG(1), ARG(2), err, sizeof err)) reply_ok(c, id);
        else reply_err(c, id, err[0] ? err : "invalid rule");
    } else if (!strcmp(cmd, "rule.localhost")) {
        NEED(2);
        if (!pu(ARG(0), 0xffffffffu, &a) || !bool_arg(ARG(1), &on)) { reply_err(c, id, "bad arguments"); return; }
        if (ProxyBridge_SetRuleLocalhost((uint32_t)a, on)) reply_ok(c, id); else reply_err(c, id, "unknown rule");
    } else if (!strcmp(cmd, "rule.enable") || !strcmp(cmd, "rule.disable")) {
        NEED(1);
        if (!pu(ARG(0), 0xffffffffu, &a)) { reply_err(c, id, "bad rule id"); return; }
        bool ok = cmd[5] == 'e' ? ProxyBridge_EnableRule((uint32_t)a) : ProxyBridge_DisableRule((uint32_t)a);
        if (ok) reply_ok(c, id); else reply_err(c, id, "unknown rule");
    } else if (!strcmp(cmd, "rule.delete")) {
        NEED(1);
        if (!pu(ARG(0), 0xffffffffu, &a)) { reply_err(c, id, "bad rule id"); return; }
        if (ProxyBridge_DeleteRule((uint32_t)a)) reply_ok(c, id); else reply_err(c, id, "unknown rule");
    } else if (!strcmp(cmd, "rule.move")) {
        NEED(2);
        if (!pu(ARG(0), 0xffffffffu, &a) || !pu(ARG(1), 100000, &b)) { reply_err(c, id, "bad arguments"); return; }
        if (ProxyBridge_MoveRule((uint32_t)a, (int)b)) reply_ok(c, id); else reply_err(c, id, "unknown rule");
    } else if (!strcmp(cmd, "rule.clear")) {
        NEED(0);
        ProxyBridge_ClearRules();
        reply_ok(c, id);
    }
    // ---- runtime switches
    else if (!strcmp(cmd, "batch.begin")) {
        NEED(0);
        ProxyBridge_BeginBatch();
        if (c->batch_depth++ == 0) c->batch_t0 = now_ms();
        reply_ok(c, id);
    } else if (!strcmp(cmd, "batch.end")) {
        NEED(0);
        if (c->batch_depth > 0) { c->batch_depth--; ProxyBridge_EndBatch(); }
        reply_ok(c, id);
    } else if (!strcmp(cmd, "cfg.dns") || !strcmp(cmd, "cfg.logEvery") || !strcmp(cmd, "cfg.logging") || !strcmp(cmd, "cfg.enabled")) {
        NEED(1);
        if (!bool_arg(ARG(0), &on)) { reply_err(c, id, "bad value"); return; }
        if (!strcmp(cmd, "cfg.dns")) ProxyBridge_SetDnsViaProxy(on);
        else if (!strcmp(cmd, "cfg.logEvery")) ProxyBridge_SetLogEveryConnection(on);
        else if (!strcmp(cmd, "cfg.logging")) { pthread_mutex_lock(&state_mu); logging_requested = on; pthread_mutex_unlock(&state_mu); update_logging(); }
        else { pthread_mutex_lock(&state_mu); engine_enabled = on; pthread_mutex_unlock(&state_mu); ProxyBridge_SetEnabled(on); }
        reply_ok(c, id);
    } else if (!strcmp(cmd, "cfg.clearLogs")) {
        NEED(0);
        ProxyBridge_ClearConnectionLogs();
        reply_ok(c, id);
    } else if (!strcmp(cmd, "engine.start")) {
        NEED(0);
        if (engine_start()) reply_ok(c, id); else reply_err(c, id, "the engine could not start; see the Activity Logs");
    } else if (!strcmp(cmd, "engine.stop")) {
        NEED(0);
        engine_stop();
        reply_ok(c, id);
    } else if (!strcmp(cmd, "flows.get")) {
        NEED(0);
        ProxyBridgeFlow *fl = calloc(PB_FLOWS_MAX, sizeof *fl);
        if (!fl) { reply_err(c, id, "out of memory"); return; }
        uint32_t n = ProxyBridge_GetFlows(fl, PB_FLOWS_MAX);
        const char **f = calloc(n + 3, sizeof *f);
        char **lines = calloc(n + 1, sizeof *lines);
        if (f && lines) {
            f[0] = "r"; f[1] = id; f[2] = "ok";
            for (uint32_t i = 0; i < n; i++) {
                char name[48], host[80];
                snprintf(name, sizeof name, "%s", fl[i].name);
                snprintf(host, sizeof host, "%s", fl[i].host);
                for (char *p = name; *p; p++) if ((unsigned char)*p < 0x20 || *p == 0x7f) *p = '?';
                for (char *p = host; *p; p++) if ((unsigned char)*p < 0x20 || *p == 0x7f) *p = '?';
                // id, pid, proxy, age_ms, sent, received, port, udp, ipv6, dest(16 bytes, hex), name, host - tab separated
                char hex[40];
                for (int k = 0; k < 16; k++) snprintf(hex + 2 * k, 3, "%02x", fl[i].dest[k]);
                if (asprintf(&lines[i], "%llu\t%u\t%u\t%u\t%llu\t%llu\t%u\t%u\t%u\t%s\t%s\t%s", (unsigned long long)fl[i].id, fl[i].pid, fl[i].proxy_id, fl[i].age_ms,
                             (unsigned long long)fl[i].sent, (unsigned long long)fl[i].received, fl[i].port, fl[i].is_udp, fl[i].is_ipv6, hex, name, host) < 0)
                    lines[i] = strdup("");
                f[3 + i] = lines[i];
            }
            send_to(c, false, n + 3, f);
        } else reply_err(c, id, "out of memory");
        if (lines) for (uint32_t i = 0; i < n; i++) free(lines[i]);
        free(lines); free(f); free(fl);
    }
    // ---- store
    else if (!strcmp(cmd, "store.list")) {
        NEED(0);
        store_list(c, id);
    } else if (!strcmp(cmd, "store.get")) {
        NEED(1);
        store_get(c, id, ARG(0));
    } else if (!strcmp(cmd, "store.put")) {
        NEED(2);
        store_put(c, id, ARG(0), ARG(1), m->len[3 + 1]);
    } else if (!strcmp(cmd, "store.delete")) {
        NEED(1);
        store_delete(c, id, ARG(0));
    } else if (!strcmp(cmd, "store.legacy")) {
        // the config.ini of 3.2.x and the Linux beta: handed to the window once, to be converted into a profile
        NEED(0);
        char path[4400];
        snprintf(path, sizeof path, "%s/config.ini", pbp_config_dir());
        struct stat lst;
        FILE *lf = lstat(path, &lst) == 0 && S_ISREG(lst.st_mode) && lst.st_size <= (1 << 20) ? fopen(path, "rb") : NULL;
        if (!lf) { reply_err(c, id, "none"); return; }
        char *lbuf = malloc((size_t)lst.st_size + 1);
        size_t ln = lbuf ? fread(lbuf, 1, (size_t)lst.st_size, lf) : 0;
        fclose(lf);
        if (!lbuf) { reply_err(c, id, "out of memory"); return; }
        lbuf[ln] = '\0';
        reply_ok1(c, id, lbuf);
        free(lbuf);
    } else if (!strcmp(cmd, "store.legacy_done")) {
        NEED(0);
        char from[4400], to[4400];
        snprintf(from, sizeof from, "%s/config.ini", pbp_config_dir());
        snprintf(to, sizeof to, "%s/config.ini.bak", pbp_config_dir());
        if (rename(from, to) != 0 && errno != ENOENT) reply_err(c, id, strerror(errno)); else reply_ok(c, id);
    } else if (!strcmp(cmd, "store.settings.get")) {
        NEED(0);
        char *active = NULL;
        bool updates = true, boot = false;
        if (read_settings(&active, &updates, &boot) != 0) { free(active); active = NULL; updates = true; boot = false; }
        const char *x[] = { active ? active : "", updates ? "1" : "0", boot ? "1" : "0" };
        reply(c, id, "ok", 3, x);
        free(active);
    } else if (!strcmp(cmd, "store.settings.set")) {
        NEED(3);
        bool updates, boot;
        if (!bool_arg(ARG(1), &updates) || !bool_arg(ARG(2), &boot)) { reply_err(c, id, "bad value"); return; }
        if (ARG(0)[0]) {                              // the active profile must be one that exists
            char *pf = name_ok(ARG(0)) ? profile_file(ARG(0)) : NULL;
            bool there = pf && access(pf, F_OK) == 0;
            free(pf);
            if (!there) { reply_err(c, id, "no such profile"); return; }
        }
        if (write_settings(ARG(0), updates, boot, err, sizeof err) != 0) reply_err(c, id, err); else reply_ok(c, id);
    }
    // ---- start at boot: the service applies the active profile when it starts and keeps routing after the window closes
    else if (!strcmp(cmd, "boot.get")) {
        NEED(0);
        bool updates = true, boot = false;
        char *active = NULL;
        if (read_settings(&active, &updates, &boot) != 0) boot = false;
        free(active);
        reply_ok1(c, id, boot ? "1" : "0");
    } else if (!strcmp(cmd, "boot.set")) {
        NEED(1);
        if (!bool_arg(ARG(0), &on)) { reply_err(c, id, "bad value"); return; }
        bool updates = true, boot = false;
        char *active = NULL;
        read_settings(&active, &updates, &boot);
        int rc = write_settings(active ? active : "", updates, on, err, sizeof err);
        free(active);
        if (rc != 0) reply_err(c, id, err); else reply_ok(c, id);
    } else {
        reply_err(c, id, "unknown command");
    }
}

static bool uid_allowed(uid_t uid);

static void *reader_main(void *arg)
{
    struct client *c = arg;
    c->last_check = time(NULL);
    for (;;) {
        // A window that opened a batch and went quiet would hold every other window's changes back from the kernel
        if (c->batch_depth > 0) {
            int64_t left = c->batch_t0 + BATCH_MAX_MS - now_ms();
            struct pollfd pf = { .fd = c->fd, .events = POLLIN };
            if (left <= 0 || poll(&pf, 1, (int)left) == 0) {
                while (c->batch_depth > 0) { c->batch_depth--; ProxyBridge_EndBatch(); }
                dlog("a window left a batch open for more than %d seconds: it was applied", BATCH_MAX_MS / 1000);
                continue;
            }
        }
        pb_msg m;
        int rc = pb_ipc_recv_timeout(c->fd, &m, BODY_TIMEOUT_MS);
        if (rc != 0) break;
        // Leaving the group ends the session, not only the next connection
        time_t now = time(NULL);
        if (now - c->last_check >= RECHECK_S) {
            c->last_check = now;
            if (!uid_allowed(c->uid)) {
                const char *f[] = { "r", m.n > 1 ? m.f[1] : "0", "err", "not allowed any more: the user left the group 'proxybridge'" };
                send_to(c, false, 4, f);
                pb_msg_free(&m);
                for (int i = 0; i < 100; i++) {          // let the writer thread deliver the explanation before the connection goes
                    pthread_mutex_lock(&c->mu);
                    bool empty = c->head == NULL;
                    pthread_mutex_unlock(&c->mu);
                    if (empty) break;
                    usleep(10000);
                }
                usleep(20000);
                break;
            }
        }
        handle(c, &m);
        pb_msg_free(&m);
    }
    // a client that vanished in the middle of a batch must not leave the kernel update held back
    while (c->batch_depth > 0) { c->batch_depth--; ProxyBridge_EndBatch(); }
    pthread_mutex_lock(&clients_mu);
    for (struct client **pp = &clients; *pp; pp = &(*pp)->next)
        if (*pp == c) { *pp = c->next; break; }
    nclients--;
    pthread_mutex_unlock(&clients_mu);
    pthread_mutex_lock(&c->mu);
    c->closing = true;
    pthread_cond_signal(&c->cv);
    pthread_mutex_unlock(&c->mu);
    shutdown(c->fd, SHUT_RDWR);
    update_logging();
    if (atomic_fetch_sub(&c->refs, 1) == 1) {
        for (struct outmsg *m = c->head; m;) { struct outmsg *n = m->next; free(m->frame); free(m); m = n; }
        close(c->fd);
        pthread_mutex_destroy(&c->mu);
        pthread_cond_destroy(&c->cv);
        free(c);
    }
    return NULL;
}

// ---- access control --------------------------------------------------------------------------------------------------------
// root, or a member of the group "proxybridge". Looked up in the group database at every connection, so adding a user to the
// group takes effect at once, without a new login. No such group: root only.
// ---- refusals --------------------------------------------------------------------------------------------------------------
#define REFUSAL_SLOTS 32
static struct { uid_t uid; int64_t until, last_log; unsigned long suppressed; } refusals[REFUSAL_SLOTS];

static bool refused_recently(uid_t uid)
{
    int64_t now = now_ms();
    for (int i = 0; i < REFUSAL_SLOTS; i++)
        if (refusals[i].until > now && refusals[i].uid == uid) return true;
    return false;
}

static void note_refusal(uid_t uid)
{
    int64_t now = now_ms();
    int slot = -1, oldest = 0;
    for (int i = 0; i < REFUSAL_SLOTS; i++) {
        if (refusals[i].uid == uid && refusals[i].last_log) { slot = i; break; }
        if (refusals[i].last_log < refusals[oldest].last_log) oldest = i;
    }
    if (slot < 0) { slot = oldest; memset(&refusals[slot], 0, sizeof refusals[slot]); refusals[slot].uid = uid; }
    refusals[slot].until = now + 1000;
    if (refusals[slot].last_log && now - refusals[slot].last_log < 60000) { refusals[slot].suppressed++; return; }
    printf("[PB] refused a connection from user %u: not root and not a member of the group '%s'%s\n", (unsigned)uid, GROUP_NAME,
           refusals[slot].suppressed ? " (more of them were refused in the last minute)" : "");
    fflush(stdout);
    refusals[slot].last_log = now;
    refusals[slot].suppressed = 0;
}

static bool uid_allowed(uid_t uid)
{
    if (uid == 0) return true;
    struct group *g = getgrnam(GROUP_NAME);
    if (!g) return false;
    struct passwd *pw = getpwuid(uid);
    if (!pw) return false;
    if (pw->pw_gid == g->gr_gid) return true;
    for (char **mem = g->gr_mem; mem && *mem; mem++)
        if (strcmp(*mem, pw->pw_name) == 0) return true;
    return false;
}

static int open_listener(const char *path)
{
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof a.sun_path) { errno = ENAMETOOLONG; return -1; }
    strcpy(a.sun_path, path);

    char dir[sizeof a.sun_path];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        if (mkdir(dir, 0755) == 0) chmod(dir, 0755);          // only a folder created here is ours to set up
        else if (errno != EEXIST) return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    unlink(path);                                   // a stale socket of a previous run
    mode_t old = umask(0);                          // everyone may connect; who may talk is decided by uid_allowed()
    int rc = bind(fd, (struct sockaddr *)&a, sizeof a);
    umask(old);
    if (rc == 0) chmod(path, 0666);
    if (rc != 0 || listen(fd, 128) != 0) { close(fd); return -1; }
    return fd;
}

int pb_daemon_run(const char *socket_path, int verbose_level)
{
    verbose = verbose_level;
    if (getuid() != 0) {
        fprintf(stderr, "ERROR: the ProxyBridge service must run as root.\n");
        return 1;
    }
    // Signals are read from a descriptor by this thread only: blocked here, so every thread started later inherits that, and
    // the service does not wake up on a timer just to look at a flag.
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGTERM);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
    int sfd = signalfd(-1, &sigs, SFD_CLOEXEC);
    if (sfd < 0) { fprintf(stderr, "ERROR: cannot watch for signals: %s\n", strerror(errno)); return 1; }

    setvbuf(stdout, NULL, _IOLBF, 0);
    ProxyBridge_SetLogCallback(on_log);
    ProxyBridge_SetConnectionCallbackEx(on_conn);
    ProxyBridge_SetTrafficLoggingEnabled(verbose == 2 || verbose == 3);

    if (!ensure_store()) { fprintf(stderr, "ERROR: cannot create %s\n", pbp_config_dir()); return 1; }
    int lfd = open_listener(socket_path);
    if (lfd < 0) { fprintf(stderr, "ERROR: cannot listen on %s: %s\n", socket_path, strerror(errno)); return 1; }
    sweep_temp_files();
    dlog("ProxyBridge service %s listening on %s", PROXYBRIDGE_VERSION, socket_path);

    // Start at Boot: route from the moment the machine is up, with the profile that was active last. Without it the service is idle
    // until a window connects and asks for the engine; closing that window switches routing off again.
    bool at_boot = false, updates = true;
    char *active = NULL;
    if (read_settings(&active, &updates, &at_boot) != 0) at_boot = false;
    free(active);
    if (at_boot) {
        apply_active_profile();
        if (!engine_start()) dlog("the engine could not start; see the lines above (needs a kernel >= 5.11 with BTF and cgroup v2)");
    } else {
        dlog("Start at Boot is off: waiting for a window");
    }

    bool stop = false;
    while (!stop) {
        struct pollfd p[2] = { { .fd = lfd, .events = POLLIN }, { .fd = sfd, .events = POLLIN } };
        int r = poll(p, 2, -1);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) continue;
        if (p[1].revents & POLLIN) {
            struct signalfd_siginfo si;
            if (read(sfd, &si, sizeof si) == (ssize_t)sizeof si && (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT)) { stop = true; break; }
        }
        if (!(p[0].revents & POLLIN)) continue;
        int fd;
        errno = 0;
        while ((fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC)) >= 0) {      // everything that is waiting, not one per wake-up
        struct ucred cred = { .pid = 0, .uid = (uid_t)-1, .gid = (gid_t)-1 };
        socklen_t cl = sizeof cred;
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl) != 0 || refused_recently(cred.uid) || !uid_allowed(cred.uid)) {
            // This path is open to every local user, so it must stay cheap: no group lookup for a user refused a moment ago, one
            // journal line per user per minute, and nothing written to the log that windows are shown.
            note_refusal(cred.uid);
            pb_ipc_sendv(fd, "r", "0", "err", "not allowed: only root and members of the group 'proxybridge' may control ProxyBridge", (char *)NULL);
            close(fd);
            continue;
        }
        pthread_mutex_lock(&clients_mu);
        bool full = nclients >= MAX_CLIENTS;
        pthread_mutex_unlock(&clients_mu);
        struct client *c = full ? NULL : calloc(1, sizeof *c);
        if (!c) {
            pb_ipc_sendv(fd, "r", "0", "err", "too many windows are connected", (char *)NULL);
            close(fd);
            continue;
        }
        c->fd = fd;
        c->uid = cred.uid;
        pthread_mutex_init(&c->mu, NULL);
        pthread_cond_init(&c->cv, NULL);
        atomic_init(&c->refs, 2);
        pthread_mutex_lock(&clients_mu);
        c->next = clients;
        clients = c;
        nclients++;
        pthread_mutex_unlock(&clients_mu);
        pthread_t rt, wt;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&wt, &at, writer_main, c) != 0) {
            pthread_mutex_lock(&clients_mu);
            for (struct client **pp = &clients; *pp; pp = &(*pp)->next) if (*pp == c) { *pp = c->next; break; }
            nclients--;
            pthread_mutex_unlock(&clients_mu);
            close(fd); free(c); pthread_attr_destroy(&at);
            continue;
        }
        if (pthread_create(&rt, &at, reader_main, c) != 0) {
            pthread_mutex_lock(&c->mu);
            c->closing = true;
            pthread_cond_signal(&c->cv);
            pthread_mutex_unlock(&c->mu);
            shutdown(fd, SHUT_RDWR);
            pthread_mutex_lock(&clients_mu);
            for (struct client **pp = &clients; *pp; pp = &(*pp)->next) if (*pp == c) { *pp = c->next; break; }
            nclients--;
            pthread_mutex_unlock(&clients_mu);
            atomic_fetch_sub(&c->refs, 1);          // the reader thread that never started
        }
        pthread_attr_destroy(&at);
        }
        if (errno == EMFILE || errno == ENFILE || errno == ENOMEM || errno == ENOBUFS) usleep(100000);    // out of descriptors: do not spin on a listener that stays readable
    }

    dlog("stopping");
    close(lfd);
    unlink(socket_path);
    engine_stop();
    return 0;
}

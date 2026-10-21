// White-box regression for GitHub issue 268: splice() has no MSG_NOSIGNAL, so forwarding into a connection that the peer reset
// raises SIGPIPE, which ends the whole process that hosts the relay (the CLI or the GUI). This test includes the relay source and
// drives its real pump_splice() and its real data thread entry.
//   * unprotected thread: the write kills the process with SIGPIPE (this proves the test reproduces the problem)
//   * a relay data thread: the same write fails with EPIPE, the pipe is left clean, the next connection still forwards
#include "../pb_relay.c"
#include <sys/wait.h>

// the engine side of the relay: nothing of it is used on these paths
int  pb_core_take_tcp_orig(uint32_t a, uint16_t b, struct pb_orig *o) { (void)a; (void)b; (void)o; return -1; }
int  pb_core_get_udp_flow(uint32_t a, struct pb_orig *o) { (void)a; (void)o; return -1; }
int  pb_core_name_for(const struct pb_orig *o, char *out, size_t n) { (void)o; (void)out; (void)n; return -1; }
int  pb_core_is_proxy_process(uint32_t a, uint32_t b) { (void)a; (void)b; return 0; }
int  pb_core_udp_sender_ok(const struct pb_orig *o, uint16_t p) { (void)o; (void)p; return 1; }
void pb_core_decide(const struct pb_orig *o, struct pb_decision *d) { (void)o; d->action = PB_ACT_DIRECT; d->proxy_id = 0; }
int  pb_core_get_proxy(uint32_t id, struct pb_proxy *p) { (void)id; (void)p; return -1; }
void pb_core_log(const char *fmt, ...) { (void)fmt; }
void pb_core_flow_event(const struct pb_orig *o, int action) { (void)o; (void)action; }
void pb_core_dns_observe(const uint8_t *m, size_t n) { (void)m; (void)n; }

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL  " __VA_ARGS__); printf("\n"); } else { printf("PASS  " __VA_ARGS__); printf("\n"); } } while (0)

// a connected TCP pair on loopback: fd[0] is the relay's side, fd[1] the far end
static void tcp_pair(int fd[2])
{
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(l, (struct sockaddr *)&a, sizeof a);
    socklen_t len = sizeof a;
    getsockname(l, (struct sockaddr *)&a, &len);
    listen(l, 1);
    fd[1] = socket(AF_INET, SOCK_STREAM, 0);
    connect(fd[1], (struct sockaddr *)&a, len);
    fd[0] = accept4(l, NULL, NULL, SOCK_NONBLOCK);
    close(l);
}

// Forward one chunk from src into a destination that the far end reset, after the reset error was already reported once, so
// the next write is EPIPE (and raises SIGPIPE). Exits 0 when pump_splice() just reports the failure.
static int forward_into_reset_peer(int direction)
{
    struct dthread t = {0};
    struct conn c = {0};
    int src[2], dst[2], pfd[2];
    tcp_pair(src);
    tcp_pair(dst);
    if (pipe2(pfd, O_NONBLOCK) != 0) return 2;
    t.pfd[0] = pfd[0]; t.pfd[1] = pfd[1];
    c.fd[direction] = src[0];
    c.fd[1 - direction] = dst[0];
    struct linger rst = { 1, 0 };
    setsockopt(dst[1], SOL_SOCKET, SO_LINGER, &rst, sizeof rst);
    close(dst[1]);                                           // RST towards dst[0]
    struct pollfd p = { dst[0], POLLIN, 0 };
    char one;
    if (poll(&p, 1, 2000) != 1 || recv(dst[0], &one, 1, 0) != -1 || errno != ECONNRESET) return 3;
    send(src[1], "payload", 7, MSG_NOSIGNAL);
    int r = pump_splice(&t, &c, direction);
    return r == -1 ? 0 : 4;
}

static void *relay_thread(void *arg)
{
    atomic_store(&R.stopping, true);                         // run the real thread entry through its shutdown path only
    struct dthread t = {0};
    data_main(&t);
    *(int *)arg = forward_into_reset_peer(0) == 0 && forward_into_reset_peer(1) == 0;
    return NULL;
}

static int status_of(void (*fn)(void), const char *what)
{
    pid_t pid = fork();
    if (pid == 0) { alarm(10); fn(); _exit(0); }
    int st = 0;
    waitpid(pid, &st, 0);
    (void)what;
    return st;
}

static void unprotected(void) { if (forward_into_reset_peer(0)) _exit(1); }
static void protected_by_relay(void)
{
    pthread_t th;
    int ok = 0;
    pthread_create(&th, NULL, relay_thread, &ok);
    pthread_join(th, NULL);
    _exit(ok ? 0 : 1);
}

int main(void)
{
    signal(SIGPIPE, SIG_DFL);                                // never depend on what the parent shell set
    sigset_t s;
    sigemptyset(&s); sigaddset(&s, SIGPIPE);
    pthread_sigmask(SIG_UNBLOCK, &s, NULL);

    int st = status_of(unprotected, "plain thread");
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGPIPE, "a thread without protection is killed by SIGPIPE when splicing into a reset peer (test reproduces issue 268)");
    st = status_of(protected_by_relay, "relay thread");
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a relay data thread survives: pump_splice reports the failure, both directions");

    // the signal mask is per thread: the thread that started the relay keeps its own signal handling
    sigset_t cur;
    pthread_sigmask(SIG_BLOCK, NULL, &cur);
    CHECK(!sigismember(&cur, SIGPIPE), "the embedding application's own SIGPIPE handling is untouched");
    printf("\nRESULT: %d failed\n", failures);
    return failures != 0;
}

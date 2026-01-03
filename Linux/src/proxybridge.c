#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "proxybridge.h"
#include "proxybridge.skel.h"

static struct proxybridge_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;
static ConnectionCallback user_callback = NULL;
static volatile sig_atomic_t should_stop = 0;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct net_event *e = data;

    (void)ctx;
    (void)data_sz;

    if (!e->daddr || !e->dport)
        return 0;

    if (user_callback)
        user_callback(e);

    return 0;
}

int ProxyBridge_Start(void)
{
    int err;

    if (skel)
        return -EBUSY;

    libbpf_set_print(NULL);

    skel = proxybridge_bpf__open();
    if (!skel)
        return -ENOMEM;

    err = proxybridge_bpf__load(skel);
    if (err)
        goto cleanup;

    err = proxybridge_bpf__attach(skel);
    if (err)
        goto cleanup;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -ENOMEM;
        goto cleanup;
    }

    should_stop = 0;
    return 0;

cleanup:
    ProxyBridge_Stop();
    return err;
}

void ProxyBridge_Stop(void)
{
    should_stop = 1;
    
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
    if (skel) {
        proxybridge_bpf__destroy(skel);
        skel = NULL;
    }
    user_callback = NULL;
}

void ProxyBridge_SetConnectionCallback(ConnectionCallback callback)
{
    user_callback = callback;
}

int ProxyBridge_Poll(int timeout_ms)
{
    if (!rb)
        return -EINVAL;

    if (should_stop)
        return 0;

    return ring_buffer__poll(rb, timeout_ms);
}

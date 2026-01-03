#ifndef __PROXYBRIDGE_H
#define __PROXYBRIDGE_H

#define TASK_COMM_LEN 16
#define PROTO_TCP 6
#define PROTO_UDP 17

struct net_event {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    char comm[TASK_COMM_LEN];
};

typedef void (*event_callback_t)(const struct net_event *event, void *ctx);

int proxybridge_init(event_callback_t callback, void *ctx);
void proxybridge_cleanup(void);
int proxybridge_poll(int timeout_ms);
void proxybridge_stop(void);

#endif

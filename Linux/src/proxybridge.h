#ifndef __PROXYBRIDGE_H
#define __PROXYBRIDGE_H

#ifdef __KERNEL__
#define PROXYBRIDGE_U32 __u32
#define PROXYBRIDGE_U16 __u16
#define PROXYBRIDGE_U8 __u8
#else
#include <stdint.h>
#define PROXYBRIDGE_U32 uint32_t
#define PROXYBRIDGE_U16 uint16_t
#define PROXYBRIDGE_U8 uint8_t
#endif

#define TASK_COMM_LEN 16
#define PROTO_TCP 6
#define PROTO_UDP 17

struct net_event {
    PROXYBRIDGE_U32 pid;
    PROXYBRIDGE_U32 saddr;
    PROXYBRIDGE_U32 daddr;
    PROXYBRIDGE_U16 sport;
    PROXYBRIDGE_U16 dport;
    PROXYBRIDGE_U8 protocol;
    char comm[TASK_COMM_LEN];
};

typedef void (*ConnectionCallback)(const struct net_event *event);

#ifdef __cplusplus
extern "C" {
#endif

int ProxyBridge_Start(void);
void ProxyBridge_Stop(void);
void ProxyBridge_SetConnectionCallback(ConnectionCallback callback);
int ProxyBridge_Poll(int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif

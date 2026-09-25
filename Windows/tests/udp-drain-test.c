#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
typedef struct {SOCKET udp_tcp_ctrl,udp_send_sock;BOOL udp_connected,setup_ready;} PB_UDP_ASSOCIATION;
typedef struct {BOOL used;PB_UDP_ASSOCIATION association;unsigned received;} PB_UDP_CLIENT;
typedef struct {int receive_cursor;WSAPOLLFD polls[12];PB_UDP_CLIENT *owners[12];BOOL controls[12];} PB_UDP_CONTEXT;
static volatile BOOL running=TRUE;
static SOCKET udp_relay_socket=1,udp_relay_socket6=2;
static unsigned total,stopAt,available4,available6,received4,received6,closed,flushed;
static char families[65];
static BOOL udp_receive_reply(PB_UDP_CONTEXT *ctx,PB_UDP_CLIENT *client){(void)ctx;++client->received;if(++total==stopAt)running=FALSE;return TRUE;}
static BOOL udp_receive_client(PB_UDP_CONTEXT *ctx,SOCKET listener,BOOL v6){
    (void)ctx;(void)listener;if(v6){if(!available6)return FALSE;--available6;families[received4+received6]='6';++received6;}
    else{if(!available4)return FALSE;--available4;families[received4+received6]='4';++received4;}return TRUE;
}
static void pb_udp_association_close(PB_UDP_ASSOCIATION *a){++closed;a->udp_connected=FALSE;}
static void udp_flush_pending(PB_UDP_ASSOCIATION *a){(void)a;++flushed;}
static int peek(SOCKET s,char *data,int length,int flags){(void)s;(void)data;(void)length;(void)flags;WSASetLastError(WSAEWOULDBLOCK);return SOCKET_ERROR;}
#define recv peek
#include "../src/relay/pb_udp_drain.inc"
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(void){
    PB_UDP_CONTEXT ctx={0};PB_UDP_CLIENT clients[8]={0};
    for(int i=0;i<8;++i){clients[i].used=clients[i].association.udp_connected=TRUE;clients[i].association.udp_send_sock=(SOCKET)(10+i);ctx.polls[2+i].fd=(SOCKET)(10+i);ctx.polls[2+i].revents=POLLRDNORM;ctx.owners[2+i]=&clients[i];}
    udp_drain_ready(&ctx,10);CHECK(total==128 && clients[0].received==32 && !clients[4].received);
    udp_drain_ready(&ctx,10);CHECK(total==256);
    for(int i=0;i<8;++i)CHECK(clients[i].received==32);
    stopAt=total+3;udp_drain_ready(&ctx,10);CHECK(total==259 && !running);
    running=TRUE;stopAt=0;ctx.polls[2].fd=999;unsigned before=clients[0].received;
    ctx.polls[9].revents=POLLERR;udp_drain_ready(&ctx,10);CHECK(clients[0].received==before && closed==1);
    available4=available6=100;udp_drain_listeners(&ctx,TRUE,TRUE);CHECK(received4==32 && received6==32);
    for(int i=0;i<64;++i)CHECK(families[i]==(i%2?'6':'4'));
    received4=received6=0;available4=1;available6=2;udp_drain_listeners(&ctx,TRUE,TRUE);CHECK(received4==1 && received6==2);
    running=FALSE;udp_drain_listeners(&ctx,TRUE,TRUE);CHECK(received4==1 && received6==2);
    puts("PASS UDP drain:32/socket,128 replies/pass, rotating fairness, Stop, stale socket/error, interleaved families and empty queues");return 0;
}

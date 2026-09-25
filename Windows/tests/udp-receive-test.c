#define main clients_regression_main
#include "udp-clients-test.c"
#undef main
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
SOCKET udp_relay_socket=1,udp_relay_socket6=2;
static BOOL packetV6;
static int receiveError,badHeader;
static unsigned receives,forwards,retired;
static struct sockaddr_in relay;
static int receive_packet(SOCKET s,char *data,int size,int flags,struct sockaddr *from,int *fromSize){
    (void)s;(void)size;(void)flags;++receives;
    if(receiveError){WSASetLastError(receiveError);return SOCKET_ERROR;}
    memcpy(from,&relay,sizeof(relay));*fromSize=sizeof(relay);
    unsigned header=packetV6?22:10;memset(data,0,header+1);data[3]=(char)(packetV6?4:1);
    data[4]=1;data[5]=2;data[6]=3;data[7]=4;data[header-2]=1;((unsigned char*)data)[header-1]=187;data[header]=0x42;
    if(badHeader)data[3]=3;
    return (int)header+1;
}
static int send_packet(SOCKET s,const char *data,int size,int flags,const struct sockaddr *to,int toSize){
    (void)s;(void)flags;(void)to;(void)toSize;if(size!=1 || data[0]!=0x42)return SOCKET_ERROR;++forwards;return size;
}
static void retire(PB_UDP_CLIENT *client){++retired;client->used=FALSE;}
static void udp_flush_pending(PB_UDP_ASSOCIATION *a){(void)a;}
static void udp_send_payload(PB_UDP_ASSOCIATION *a,const unsigned char *data,int length){(void)a;(void)data;(void)length;}
void snoop_dns_response(const unsigned char *data,int length){(void)data;(void)length;}
#define recvfrom receive_packet
#define sendto send_packet
#define udp_retire_client retire
#include "../src/relay/pb_udp_receive.inc"
int main(void){
    relay.sin_family=AF_INET;relay.sin_port=htons(12345);relay.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    PB_UDP_CONTEXT *ctx=calloc(1,sizeof(*ctx));CHECK(ctx);
    for(unsigned v6=0;v6<2;++v6){
        PB_UDP_CLIENT client={0};client.used=TRUE;client.pid=123;client.mapping_generation=1;client.destination_port=443;
        client.destination[0]=1;client.destination[1]=2;client.destination[2]=3;client.destination[3]=4;
        client.association.udp_relay_addr=relay;packetV6=v6;
        if(v6){struct sockaddr_in6 *source=(struct sockaddr_in6*)&client.source;source->sin6_family=AF_INET6;source->sin6_port=htons(10000);}
        else{struct sockaddr_in *source=(struct sockaddr_in*)&client.source;source->sin_family=AF_INET;source->sin_port=htons(10000);}
        ctx->driver_epoch=epoch;ctx->definition_revision=g_proxy_revision;query_error=0;mutation=0;
        unsigned before=forwards,queries=query_count;
        for(unsigned i=0;i<32;++i)CHECK(udp_receive_reply(ctx,&client));
        CHECK(forwards==before+32 && query_count==queries+32);
        mutation=1;CHECK(!udp_receive_reply(ctx,&client) && !client.used && forwards==before+32);
        mutation=0;client.used=TRUE;
        unsigned reads=receives;++epoch;CHECK(!udp_receive_reply(ctx,&client) && receives==reads);ctx->driver_epoch=epoch;
        ++g_proxy_revision;CHECK(!udp_receive_reply(ctx,&client) && receives==reads);ctx->definition_revision=g_proxy_revision;
        queries=query_count;badHeader=1;CHECK(udp_receive_reply(ctx,&client) && query_count==queries);badHeader=0;
        receiveError=WSAEWOULDBLOCK;CHECK(!udp_receive_reply(ctx,&client));
        unsigned closed=closed_count;receiveError=WSAECONNRESET;CHECK(!udp_receive_reply(ctx,&client) && closed_count==closed+1);
        receiveError=0;
    }
    free(ctx);puts("PASS UDP per-packet receive: IPv4/IPv6 ownership on every packet, changed generation/epoch/proxy rejection, malformed header and socket errors");return 0;
}


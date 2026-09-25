#define PB_UDP_RECEIVE_BURST 32u
#define PB_UDP_REPLY_BUDGET 128u
// No socket creation or client reassignment while consuming a poll snapshot.
// A per-socket cap plus rotating global budget prevents a busy prefix from
// excluding later sockets. Errors/control events never consume the data budget.
static void udp_drain_ready(PB_UDP_CONTEXT *ctx,int count)
{
    int entries=count-2;
    if(entries<=0)return;
    int start=ctx->receive_cursor%entries;
    unsigned budget=PB_UDP_REPLY_BUDGET;
    for(int offset=0;running && offset<entries;++offset){
        int i=2+(start+offset)%entries;
        if(!ctx->polls[i].revents)continue;
        PB_UDP_CLIENT *client=ctx->owners[i];
        PB_UDP_ASSOCIATION *a=&client->association;
        SOCKET current=ctx->controls[i]?a->udp_tcp_ctrl:a->udp_send_sock;
        if(!client->used || current!=ctx->polls[i].fd)continue;
        if(ctx->polls[i].revents&(POLLERR|POLLHUP|POLLNVAL))pb_udp_association_close(a);
        else if(!a->udp_connected && ctx->controls[i])a->setup_ready=TRUE;
        else if(ctx->controls[i]){
            char byte;int result=recv(current,&byte,1,MSG_PEEK);
            if(result>=0 || WSAGetLastError()!=WSAEWOULDBLOCK)pb_udp_association_close(a);
        } else {
            if(ctx->polls[i].revents&POLLWRNORM)udp_flush_pending(a);
            if(a->udp_connected && (ctx->polls[i].revents&POLLRDNORM) && budget){
                ctx->receive_cursor=(i-1)%entries;
                for(unsigned packet=0;running && budget && packet<PB_UDP_RECEIVE_BURST;++packet){
                    if(!udp_receive_reply(ctx,client))break;
                    --budget;
                }
            }
        }
    }
}
static void udp_drain_listeners(PB_UDP_CONTEXT *ctx,BOOL ready4,BOOL ready6)
{
    // Interleave families so an IPv4 burst does not postpone every IPv6 packet.
    for(unsigned packet=0;running && packet<PB_UDP_RECEIVE_BURST && (ready4 || ready6);++packet){
        if(ready4)ready4=udp_receive_client(ctx,udp_relay_socket,FALSE);
        if(running && ready6)ready6=udp_receive_client(ctx,udp_relay_socket6,TRUE);
    }
}

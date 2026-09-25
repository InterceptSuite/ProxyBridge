// Relay control phase only: one deadline, no allocations, nonblocking socket.
// NULL context preserves standalone proxy-check socket behavior.
static int handshake_transfer(SOCKET s, char* buffer, int length, BOOL write, BOOL exact,
                    const PB_HANDSHAKE_CONTEXT* context, int flags)
{
    if (!context) return write ? send(s,buffer,length,0) :
        exact ? recv_n(s,buffer,length) : recv(s,buffer,length,flags);
    int done=0;
    while (done<length) {
        if (!running) { WSASetLastError(WSAEINTR); return SOCKET_ERROR; }
        ULONGLONG now=GetTickCount64();
        if (now>=context->deadline) { WSASetLastError(WSAETIMEDOUT); return SOCKET_ERROR; }
        int count=write ? send(s,buffer+done,length-done,0) : recv(s,buffer+done,length-done,flags);
        if (count>0) { done+=count; if (!exact) return done; continue; }
        if (!count) { WSASetLastError(WSAECONNRESET); return SOCKET_ERROR; }
        if (WSAGetLastError()!=WSAEWOULDBLOCK) return SOCKET_ERROR;
        now=GetTickCount64();
        if (now>=context->deadline) { WSASetLastError(WSAETIMEDOUT); return SOCKET_ERROR; }
        DWORD wait=(DWORD)min(context->deadline-now,100);
        struct timeval timeout={0,(long)wait*1000};
        fd_set ready; FD_ZERO(&ready); FD_SET(s,&ready);
        if (select(0,write ? NULL : &ready,write ? &ready : NULL,NULL,&timeout)==SOCKET_ERROR)
            return SOCKET_ERROR;
    }
    return done;
}
int pb_handshake_io(SOCKET s, char* buffer, int length, BOOL write, BOOL exact,
                    const PB_HANDSHAKE_CONTEXT* context)
{ return handshake_transfer(s,buffer,length,write,exact,context,0); }
int pb_handshake_peek(SOCKET s, char* buffer, int length, const PB_HANDSHAKE_CONTEXT* context)
{ return handshake_transfer(s,buffer,length,FALSE,FALSE,context,MSG_PEEK); }

// Consume only the complete header section, preserving coalesced tunnel bytes.
// The handshake owns the socket exclusively. Peek + exact consume costs two
// receives for the usual single-chunk header, with no extra allocation.
static int http_read_headers(SOCKET s, char* response, int capacity,
                              const PB_HANDSHAKE_CONTEXT* context)
{
    int used=0;
    while (used<capacity-1) {
        int count=pb_handshake_peek(s,response+used,capacity-1-used,context);
        if (count<=0) return -1;
        int end=0;
        for (int i=max(0,used-3); i+3<used+count; i++) {
            if (!memcmp(response+i,"\r\n\r\n",4)) { end=i+4; break; }
        }
        int take=end ? end-used : count;
        if (pb_handshake_io(s,response+used,take,FALSE,TRUE,context)!=take) return -1;
        used+=take;
        if (end) { response[used]='\0'; return used; }
    }
    WSASetLastError(WSAEMSGSIZE); return -1;
}

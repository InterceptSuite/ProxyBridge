// test_proxy_protocols.c - the proxy client handshakes (src\pb_socks5.c, src\pb_http.c) against a scripted fake
// proxy server on loopback (ephemeral port, one short connection per case; no driver, no real proxy):
//   SOCKS5: greeting, username/password auth, CONNECT (IPv4, IPv6, domain), every reply code, every BND.ADDR type,
//           malformed and truncated replies, UDP ASSOCIATE
//   HTTP:   CONNECT request format, Proxy-Authorization, status handling, cached host names, over-long requests
#include "pb_internal.h"
#include "pbtest.h"

typedef struct {
    BYTE method;               /* SOCKS5: auth method the server picks (0 none, 2 user/pass, 0xFF unacceptable, ...) */
    BYTE auth_status;          /* SOCKS5: 0 = credentials accepted */
    BYTE reply[600]; int reply_len;   /* raw reply sent after the request (SOCKS5 reply / HTTP response) */
    int  close_at;             /* 1 = close after the greeting, 2 = after auth, 3 = after the request without a reply */
    BOOL http;
    /* captured */
    BYTE greeting[16]; int greeting_len;
    char user[300], pass[300];
    BYTE req[600]; int req_len;
    char http_req[4096]; int http_len;
} Script;

typedef struct { SOCKET listener; Script* sc; HANDLE thread; } Srv;

static BOOL rx(SOCKET s, BYTE* b, int n) { int got = 0; while (got < n) { int r = recv(s, (char*)b + got, n - got, 0); if (r <= 0) return FALSE; got += r; } return TRUE; }

static DWORD WINAPI server_thread(LPVOID p)
{
    Srv* sv = (Srv*)p; Script* sc = sv->sc;
    SOCKET c = accept(sv->listener, NULL, NULL);
    if (c == INVALID_SOCKET) return 0;
    DWORD to = 3000; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof to);
    BYTE b[1100];

    if (sc->http)
    {
        int n = 0;
        while (n < (int)sizeof(sc->http_req) - 1)
        {
            int r = recv(c, sc->http_req + n, 1, 0); if (r <= 0) break; n++; sc->http_req[n] = 0;
            if (n >= 4 && !strcmp(sc->http_req + n - 4, "\r\n\r\n")) break;
        }
        sc->http_len = n;
        if (sc->reply_len) send(c, (char*)sc->reply, sc->reply_len, 0);
        closesocket(c); return 0;
    }

    if (!rx(c, b, 2)) { closesocket(c); return 0; }
    int nm = b[1]; if (nm > 14) nm = 14;
    if (nm && !rx(c, b + 2, nm)) { closesocket(c); return 0; }
    sc->greeting_len = 2 + nm; memcpy(sc->greeting, b, sc->greeting_len);
    if (sc->close_at == 1) { closesocket(c); return 0; }
    BYTE sel[2] = { 5, sc->method }; send(c, (char*)sel, 2, 0);
    if (sc->method == 2)
    {
        if (!rx(c, b, 2)) { closesocket(c); return 0; }
        int ul = b[1]; if (!rx(c, b + 2, ul + 1)) { closesocket(c); return 0; }
        memcpy(sc->user, b + 2, ul); sc->user[ul] = 0;
        int pl = b[2 + ul]; if (!rx(c, b + 3 + ul, pl)) { closesocket(c); return 0; }
        memcpy(sc->pass, b + 3 + ul, pl); sc->pass[pl] = 0;
        BYTE ar[2] = { 1, sc->auth_status }; send(c, (char*)ar, 2, 0);
        if (sc->auth_status != 0 || sc->close_at == 2) { closesocket(c); return 0; }
    }
    else if (sc->method != 0) { closesocket(c); return 0; }

    if (!rx(c, b, 4)) { closesocket(c); return 0; }
    int rest = (b[3] == 1) ? 6 : (b[3] == 4) ? 18 : 0;
    if (b[3] == 3) { if (!rx(c, b + 4, 1)) { closesocket(c); return 0; } rest = b[4] + 2; if (!rx(c, b + 5, rest)) { closesocket(c); return 0; } sc->req_len = 5 + rest; }
    else           { if (rest && !rx(c, b + 4, rest)) { closesocket(c); return 0; } sc->req_len = 4 + rest; }
    memcpy(sc->req, b, sc->req_len);
    if (sc->close_at != 3 && sc->reply_len) send(c, (char*)sc->reply, sc->reply_len, 0);
    Sleep(20);                                   /* let the client read the reply before the FIN */
    closesocket(c); return 0;
}

/* starts the fake server and returns a connected client socket */
static SOCKET start(Srv* sv, Script* sc)
{
    memset(sv, 0, sizeof *sv); sv->sc = sc;
    sv->listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(sv->listener, (struct sockaddr*)&a, sizeof a); listen(sv->listener, 1);
    int len = sizeof a; getsockname(sv->listener, (struct sockaddr*)&a, &len);
    sv->thread = CreateThread(NULL, 0, server_thread, sv, 0, NULL);
    SOCKET c = socket(AF_INET, SOCK_STREAM, 0);
    DWORD to = 3000; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof to);
    connect(c, (struct sockaddr*)&a, sizeof a);
    return c;
}
static void finish(Srv* sv, SOCKET c) { closesocket(c); WaitForSingleObject(sv->thread, 8000); CloseHandle(sv->thread); closesocket(sv->listener); }

static UINT32 ip4(const char* s) { struct in_addr a; inet_pton(AF_INET, s, &a); return a.S_un.S_addr; }
static void set_reply(Script* sc, const BYTE* r, int n) { memcpy(sc->reply, r, n); sc->reply_len = n; }
static void set_text(Script* sc, const char* t) { sc->reply_len = (int)strlen(t); memcpy(sc->reply, t, sc->reply_len); }

/* one SOCKS5 IPv4 CONNECT with a given reply; returns the client's result */
static int s5_v4(Script* sc, const PROXY_CONFIG* cfg)
{
    Srv sv; SOCKET c = start(&sv, sc);
    int r = socks5_connect(c, ip4("1.2.3.4"), 443, cfg);
    finish(&sv, c); return r;
}
static const BYTE OKREPLY[10] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };

int main(void)
{
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    PROXY_CONFIG none; memset(&none, 0, sizeof none);
    PROXY_CONFIG auth; memset(&auth, 0, sizeof auth); strcpy_s(auth.username, sizeof auth.username, "alice"); strcpy_s(auth.password, sizeof auth.password, "s3cret");
    Script sc;

    /* ---- SOCKS5 CONNECT, no authentication ---- */
    memset(&sc, 0, sizeof sc); set_reply(&sc, OKREPLY, 10);
    CHECK(s5_v4(&sc, &none) == 0);
    CHECK(sc.greeting_len == 3 && sc.greeting[0] == 5 && sc.greeting[1] == 1 && sc.greeting[2] == 0);        /* offers "no auth" only */
    CHECK(sc.req_len == 10 && !memcmp(sc.req, "\x05\x01\x00\x01\x01\x02\x03\x04\x01\xBB", 10));                  /* CONNECT 1.2.3.4:443 */

    /* ---- username/password (RFC 1929) ---- */
    memset(&sc, 0, sizeof sc); sc.method = 2; set_reply(&sc, OKREPLY, 10);
    CHECK(s5_v4(&sc, &auth) == 0);
    CHECK(sc.greeting_len == 4 && sc.greeting[1] == 2 && sc.greeting[2] == 0 && sc.greeting[3] == 2);          /* offers none + user/pass */
    CHECK(!strcmp(sc.user, "alice") && !strcmp(sc.pass, "s3cret"));
    memset(&sc, 0, sizeof sc); sc.method = 2; sc.auth_status = 1; set_reply(&sc, OKREPLY, 10);
    CHECK(s5_v4(&sc, &auth) == -1);                                                                              /* wrong password */
    memset(&sc, 0, sizeof sc); sc.method = 2; set_reply(&sc, OKREPLY, 10);
    CHECK(s5_v4(&sc, &none) == -1);                                                                              /* server wants auth, we have none */
    memset(&sc, 0, sizeof sc); sc.method = 0xFF; set_reply(&sc, OKREPLY, 10);
    CHECK(s5_v4(&sc, &none) == -1);                                                                              /* no acceptable method */
    memset(&sc, 0, sizeof sc); sc.method = 3; set_reply(&sc, OKREPLY, 10);
    CHECK(s5_v4(&sc, &none) == -1);                                                                              /* unsupported method */
    { PROXY_CONFIG big = auth; memset(big.username, 'u', 255); big.username[255] = 0; memset(big.password, 'p', 255); big.password[255] = 0;
      memset(&sc, 0, sizeof sc); sc.method = 2; set_reply(&sc, OKREPLY, 10);
      CHECK(s5_v4(&sc, &big) == 0 && strlen(sc.user) == 255 && strlen(sc.pass) == 255); }                      /* longest credentials fit */

    /* ---- every REP code is a failure ---- */
    for (int rep = 1; rep <= 8; rep++)
    {
        BYTE r[10] = { 5, (BYTE)rep, 0, 1, 0, 0, 0, 0, 0, 0 };
        memset(&sc, 0, sizeof sc); set_reply(&sc, r, 10);
        CHECK(s5_v4(&sc, &none) == -1);
    }

    /* ---- BND.ADDR of any type is parsed and drained, whatever the request used ---- */
    { BYTE r[22] = { 5, 0, 0, 4 }; memset(&sc, 0, sizeof sc); set_reply(&sc, r, 22); CHECK(s5_v4(&sc, &none) == 0); }          /* IPv6 */
    { BYTE r[8] = { 5, 0, 0, 3, 5, 'a', 'b', 'c' };  memcpy(r + 8 - 0, "", 0);
      BYTE full[4 + 1 + 5 + 2] = { 5, 0, 0, 3, 5, 'a', 'b', 'c', 'd', 'e', 0, 80 }; memset(&sc, 0, sizeof sc); set_reply(&sc, full, sizeof full); CHECK(s5_v4(&sc, &none) == 0); (void)r; }
    { BYTE full[4 + 1 + 255 + 2] = { 5, 0, 0, 3, 255 }; memset(&sc, 0, sizeof sc); set_reply(&sc, full, sizeof full); CHECK(s5_v4(&sc, &none) == 0); }   /* longest domain */
    { BYTE r[10] = { 5, 0, 0, 9, 0, 0, 0, 0, 0, 0 };  memset(&sc, 0, sizeof sc); set_reply(&sc, r, 10); CHECK(s5_v4(&sc, &none) == -1); }    /* unknown ATYP */
    { BYTE r[10] = { 4, 0, 0, 1, 0, 0, 0, 0, 0, 0 };  memset(&sc, 0, sizeof sc); set_reply(&sc, r, 10); CHECK(s5_v4(&sc, &none) == -1); }    /* wrong version */
    { BYTE r[6]  = { 5, 0, 0, 1, 0, 0 };              memset(&sc, 0, sizeof sc); set_reply(&sc, r, 6);  CHECK(s5_v4(&sc, &none) == -1); }    /* truncated, then closed */
    { BYTE r[3]  = { 5, 0, 0 };                       memset(&sc, 0, sizeof sc); set_reply(&sc, r, 3);  CHECK(s5_v4(&sc, &none) == -1); }
    memset(&sc, 0, sizeof sc); sc.close_at = 1; set_reply(&sc, OKREPLY, 10); CHECK(s5_v4(&sc, &none) == -1);   /* server hangs up after the greeting */
    memset(&sc, 0, sizeof sc); sc.close_at = 3; set_reply(&sc, OKREPLY, 10); CHECK(s5_v4(&sc, &none) == -1);   /* ... or after the request, without a reply */

    /* ---- CONNECT by domain name ---- */
    { Srv sv; memset(&sc, 0, sizeof sc); set_reply(&sc, OKREPLY, 10);
      SOCKET c = start(&sv, &sc); int r = socks5_connect_domain(c, "example.com", 8443, &none); finish(&sv, c);
      CHECK(r == 0 && sc.req[3] == 3 && sc.req[4] == 11 && !memcmp(sc.req + 5, "example.com", 11) && sc.req[16] == 0x20 && sc.req[17] == 0xFB); }
    { Srv sv; memset(&sc, 0, sizeof sc); set_reply(&sc, OKREPLY, 10);
      SOCKET c = start(&sv, &sc); int r = socks5_connect_domain(c, "", 80, &none); finish(&sv, c); CHECK(r == -1); }               /* empty name */
    { char name[300]; memset(name, 'a', 299); name[299] = 0; Srv sv; memset(&sc, 0, sizeof sc); set_reply(&sc, OKREPLY, 10);
      SOCKET c = start(&sv, &sc); int r = socks5_connect_domain(c, name, 80, &none); finish(&sv, c);
      CHECK(r == 0 && sc.req[4] == 255 && sc.req_len == 5 + 255 + 2); }                                                           /* over-long name is cut to 255, never overflows */

    /* ---- CONNECT by IPv6 address ---- */
    { UINT8 a6[16]; inet_pton(AF_INET6, "2001:db8::7", a6); Srv sv; memset(&sc, 0, sizeof sc); set_reply(&sc, OKREPLY, 10);
      SOCKET c = start(&sv, &sc); int r = socks5_connect_v6(c, a6, 443, &none); finish(&sv, c);
      CHECK(r == 0 && sc.req[3] == 4 && !memcmp(sc.req + 4, a6, 16) && sc.req[20] == 0x01 && sc.req[21] == 0xBB); }

    /* ---- UDP ASSOCIATE ---- */
    { BYTE r[10] = { 5, 0, 0, 1, 127, 0, 0, 1, 0x15, 0xB3 };            /* relay 127.0.0.1:5555 */
      Srv sv; memset(&sc, 0, sizeof sc); set_reply(&sc, r, 10);
      SOCKET c = start(&sv, &sc); struct sockaddr_in ra; memset(&ra, 0, sizeof ra);
      int rc = socks5_udp_associate_with_config(c, &ra, &none); finish(&sv, c);
      CHECK(rc == 0 && sc.req[1] == 3 && ra.sin_family == AF_INET && ra.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && ntohs(ra.sin_port) == 5555); }
    { BYTE r[22] = { 5, 0, 0, 4 };                                       /* IPv6 relay endpoint cannot be used */
      Srv sv; memset(&sc, 0, sizeof sc); set_reply(&sc, r, 22);
      SOCKET c = start(&sv, &sc); struct sockaddr_in ra; memset(&ra, 0, sizeof ra); int rc = socks5_udp_associate_with_config(c, &ra, &none); finish(&sv, c); CHECK(rc == -1); }
    { BYTE r[10] = { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 };                     /* command not supported */
      Srv sv; memset(&sc, 0, sizeof sc); set_reply(&sc, r, 10);
      SOCKET c = start(&sv, &sc); struct sockaddr_in ra; memset(&ra, 0, sizeof ra); int rc = socks5_udp_associate_with_config(c, &ra, &none); finish(&sv, c); CHECK(rc == -1); }

    /* ================= HTTP CONNECT ================= */
    dns_cache_init();
    { Srv sv; memset(&sc, 0, sizeof sc); sc.http = TRUE; set_text(&sc, "HTTP/1.1 200 Connection established\r\n\r\n");
      SOCKET c = start(&sv, &sc); int r = http_connect(c, ip4("1.2.3.4"), 443, &none); finish(&sv, c);
      CHECK(r == 0);
      CHECK(strncmp(sc.http_req, "CONNECT 1.2.3.4:443 HTTP/1.1\r\n", 30) == 0 && strstr(sc.http_req, "Host: 1.2.3.4:443\r\n") && !strstr(sc.http_req, "Proxy-Authorization")); }
    { Srv sv; memset(&sc, 0, sizeof sc); sc.http = TRUE; set_text(&sc, "HTTP/1.0 200 OK\r\n\r\n");
      SOCKET c = start(&sv, &sc); int r = http_connect(c, ip4("1.2.3.4"), 443, &auth); finish(&sv, c);
      CHECK(r == 0 && strstr(sc.http_req, "Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n") != NULL); }        /* base64("alice:s3cret") */
    { const char* bad[] = { "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "HTTP/1.1 502 Bad Gateway\r\n\r\n", "HTTP/1.1 403 Forbidden\r\n\r\n",
                            "SSH-2.0-OpenSSH_9.0\r\n", "HTTP/1.1\r\n\r\n", "HTTP/1.1 abc\r\n\r\n", "" };
      for (int i = 0; i < 7; i++)
      { Srv sv; memset(&sc, 0, sizeof sc); sc.http = TRUE; set_text(&sc, bad[i]);
        SOCKET c = start(&sv, &sc); int r = http_connect(c, ip4("1.2.3.4"), 443, &none); finish(&sv, c); CHECK(r == -1); } }
    /* a cached host name is used only when the proxy config asks for it */
    dns_cache_store(ip4("93.184.216.34"), "example.com");
    { PROXY_CONFIG withDomain = none; withDomain.send_domain_to_proxy = TRUE;
      Srv sv; memset(&sc, 0, sizeof sc); sc.http = TRUE; set_text(&sc, "HTTP/1.1 200 OK\r\n\r\n");
      SOCKET c = start(&sv, &sc); int r = http_connect(c, ip4("93.184.216.34"), 80, &withDomain); finish(&sv, c);
      CHECK(r == 0 && strncmp(sc.http_req, "CONNECT example.com:80 HTTP/1.1", 31) == 0);
      memset(&sc, 0, sizeof sc); sc.http = TRUE; set_text(&sc, "HTTP/1.1 200 OK\r\n\r\n");
      c = start(&sv, &sc); r = http_connect(c, ip4("93.184.216.34"), 80, &none); finish(&sv, c);
      CHECK(r == 0 && strncmp(sc.http_req, "CONNECT 93.184.216.34:80 HTTP/1.1", 33) == 0); }
    { UINT8 a6[16]; inet_pton(AF_INET6, "2001:db8::7", a6); Srv sv; memset(&sc, 0, sizeof sc); sc.http = TRUE; set_text(&sc, "HTTP/1.1 200 OK\r\n\r\n");
      SOCKET c = start(&sv, &sc); int r = http_connect_v6(c, a6, 443, &none); finish(&sv, c);
      CHECK(r == 0 && strncmp(sc.http_req, "CONNECT [2001:db8::7]:443 HTTP/1.1", 34) == 0); }

    /* a request that does not fit its buffer (very long credentials AND a very long cached name) must be refused:
       send() must never be asked for more bytes than the buffer holds (that would leak stack memory to the proxy) */
    { PROXY_CONFIG big = auth; big.send_domain_to_proxy = TRUE;
      memset(big.username, 'u', 255); big.username[255] = 0; memset(big.password, 'p', 255); big.password[255] = 0;
      char longname[256]; memset(longname, 'n', 240); strcpy_s(longname + 240, sizeof longname - 240, ".example.com");
      dns_cache_store(ip4("203.0.113.9"), longname);
      Srv sv; memset(&sc, 0, sizeof sc); sc.http = TRUE; set_text(&sc, "HTTP/1.1 200 OK\r\n\r\n");
      SOCKET c = start(&sv, &sc); int r = http_connect(c, ip4("203.0.113.9"), 443, &big); finish(&sv, c);
      CHECK(r == -1);
      CHECK(sc.http_len <= HTTP_BUFFER_SIZE); }

    WSACleanup();
    return pbtest_done("test_proxy_protocols");
}

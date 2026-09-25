// Test DLL: real Core lifecycle and relays; no driver implementation linked.
#include "pb_internal.h"
#include "../shared/update-guard.h"
#include "../installer/install-store.h"
#include "../installer/install-selection.h"
#include "../src/driver/ProxyBridgeDrv_ioctl.h"
static DWORD test_guard(HANDLE* guard) { *guard = NULL; return ERROR_SUCCESS; }
static DWORD test_store(BOOL create, HKEY* key)
{ (void)create; *key = NULL; return ERROR_FILE_NOT_FOUND; }
#define pb_update_guard_acquire test_guard
#define pb_install_store_open test_store
#include "../src/core/ProxyBridge.c"
#undef pb_install_store_open
#undef pb_update_guard_acquire
static BOOL driverActive, failDriver;
BOOL g_use_wfp_driver = TRUE;
BOOL pb_driver_start(UINT16 port)
{ (void)port; if (failDriver) { SetLastError(ERROR_GEN_FAILURE); return FALSE; } driverActive=TRUE; return TRUE; }
void pb_driver_stop(void) { driverActive=FALSE; }
BOOL pb_driver_is_active(void) { return driverActive; }
BOOL pb_driver_is_worker_thread(void) { return FALSE; }
LONG64 pb_driver_session_epoch(void) { return 1; }
PBDRV_WATCHLIST* pb_driver_prepare_rules(const PROCESS_RULE* rules)
{ (void)rules; return calloc(1,sizeof(PBDRV_WATCHLIST)); }
BOOL pb_driver_apply_rules(const PBDRV_WATCHLIST* watch) { (void)watch; return TRUE; }
BOOL pb_driver_apply_profile_rules(const PBDRV_WATCHLIST* watch, BOOL loopback)
{ (void)watch; (void)loopback; return TRUE; }
BOOL pb_driver_orig_dest(SOCKET s, UINT32* ip, UINT16* port, DWORD* pid)
{ (void)s; (void)ip; (void)port; (void)pid; return FALSE; }
BOOL pb_driver_orig_dest6(SOCKET s, UINT8 ip[16], UINT16* port, DWORD* pid)
{ (void)s; (void)ip; (void)port; (void)pid; return FALSE; }
BOOL pb_driver_udp_orig(UINT32 src, UINT16 sp, UINT32* ip, UINT16* port, DWORD* pid, UINT64* gen)
{ (void)src; (void)sp; (void)ip; (void)port; (void)pid; (void)gen; SetLastError(ERROR_NOT_FOUND); return FALSE; }
BOOL pb_driver_udp_orig6(const UINT8 src[16], UINT16 sp, UINT8 ip[16], UINT16* port, DWORD* pid, UINT64* gen)
{ (void)src; (void)sp; (void)ip; (void)port; (void)pid; (void)gen; SetLastError(ERROR_NOT_FOUND); return FALSE; }
#define CHECK(x) do { if (!(x)) { printf("FAIL lifecycle line %d error %lu\n",__LINE__,GetLastError()); return 1; } } while(0)
BOOL test_start_handshake(CONNECTION_CONFIG* config);
BOOL test_tcp_clean(void);
#include "tcp-test-sockets.inc"
static HANDLE callbackDone;
static BOOL callbackStopResult;
static DWORD callbackStopError;
static void reentry_log(const char* message)
{
    if (!strstr(message,"No proxy config")) return;
    callbackStopResult=ProxyBridge_Stop(); callbackStopError=GetLastError();
    SetEvent(callbackDone);
}
static DWORD WINAPI stop_core(void* arg)
{ (void)arg; return ProxyBridge_Stop() ? 0 : 1; }
static int test_worker_reentry(void)
{
    CHECK(ProxyBridge_Start());
    SOCKET client,input;
    CHECK(socket_pair(&client,&input));
    CONNECTION_CONFIG* config=calloc(1,sizeof(*config)); CHECK(config);
    config->client_socket=input; // empty proxy triggers log inside handshake worker
    callbackDone=CreateEventW(NULL,TRUE,FALSE,NULL); CHECK(callbackDone);
    ProxyBridge_SetLogCallback(reentry_log);
    CHECK(test_start_handshake(config));
    CHECK(WaitForSingleObject(callbackDone,3000)==WAIT_OBJECT_0);
    CHECK(!callbackStopResult && callbackStopError==ERROR_BUSY);
    CHECK(ProxyBridge_IsFilteringActive() && running);
    CHECK(ProxyBridge_Stop()); // joins callback thread before removing its storage
    ProxyBridge_SetLogCallback(NULL);
    CloseHandle(callbackDone); closesocket(client);
    CHECK(test_tcp_clean());
    puts("PASS Core handshake callback Stop rejects self-join; external Stop succeeds");
    return 0;
}
static int test_handshake_stop(BOOL complete, BOOL http)
{
    CHECK(ProxyBridge_Start());
    SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); CHECK(listener!=INVALID_SOCKET);
    struct sockaddr_in address={0}; address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); int size=sizeof(address);
    CHECK(!bind(listener,(struct sockaddr*)&address,size) && !listen(listener,1));
    CHECK(!getsockname(listener,(struct sockaddr*)&address,&size));
    SOCKET client,input; CHECK(socket_pair(&client,&input));
    CONNECTION_CONFIG* config=calloc(1,sizeof(*config)); CHECK(config);
    config->client_socket=input; config->orig_dest_ip=htonl(INADDR_LOOPBACK); config->orig_dest_port=443;
    config->proxy_snapshot.type=http ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
    strcpy_s(config->proxy_snapshot.host,sizeof(config->proxy_snapshot.host),"127.0.0.1");
    config->proxy_snapshot.resolved_ip=address.sin_addr.s_addr;
    config->proxy_snapshot.port=ntohs(address.sin_port);
    CHECK(test_start_handshake(config));
    fd_set ready; FD_ZERO(&ready); FD_SET(listener,&ready); struct timeval timeout={3,0};
    CHECK(select(0,&ready,NULL,NULL,&timeout)==1);
    SOCKET server=accept(listener,NULL,NULL); closesocket(listener); CHECK(server!=INVALID_SOCKET);
    DWORD socketTimeout=2000;
    CHECK(!setsockopt(server,SOL_SOCKET,SO_RCVTIMEO,(char*)&socketTimeout,sizeof(socketTimeout)));
    CHECK(!setsockopt(server,SOL_SOCKET,SO_SNDTIMEO,(char*)&socketTimeout,sizeof(socketTimeout)));
    if (http) {
        char header[2048]={0}; int used=0;
        while (used<sizeof(header)-1 && (used<4 || memcmp(header+used-4,"\r\n\r\n",4))) {
            CHECK(recv(server,header+used,1,0)==1); used++;
        }
        CHECK(strstr(header,"CONNECT 127.0.0.1:443 HTTP/1.1\r\n")==header);
        if (complete) {
            // TCP may coalesce CONNECT headers with the first tunneled bytes.
            CHECK(send_all(server,"HTTP/1.1 200 OK\r\n\r\nearly",24)==24);
            CHECK(read_exact(client,"early",5));
        }
    } else {
        CHECK(read_exact(server,"\x05\x01\x00",3));
        if (complete) {
        CHECK(send_all(server,"\x05",1)==1 && send_all(server,"\x00",1)==1);
        CHECK(read_exact(server,"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb",10));
        CHECK(send_all(server,"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb",10)==10);
        }
    }
    if (complete) {
        CHECK(send_all(client,"data",4)==4 && read_exact(server,"data",4));
        CHECK(send_all(server,"reply",5)==5 && read_exact(client,"reply",5));
    }
    HANDLE stopper=CreateThread(NULL,0,stop_core,NULL,0,NULL); CHECK(stopper);
    CHECK(WaitForSingleObject(stopper,4000)==WAIT_OBJECT_0);
    DWORD result; CHECK(GetExitCodeThread(stopper,&result) && result==0); CloseHandle(stopper);
    CHECK(test_tcp_clean());
    char byte; int rc=recv(server,&byte,1,0);
    CHECK(rc==0 || (rc==SOCKET_ERROR && WSAGetLastError()!=WSAETIMEDOUT));
    closesocket(client); closesocket(server);
    printf("PASS Core Stop during %s %s with real handshake worker and sockets\n",
        http ? "HTTP CONNECT" : "SOCKS5", complete ? "established bidirectional stream" : "stalled handshake");
    return 0;
}
static BOOL stopped_clean(void)
{
    return g_lifecycle_state == PB_STOPPED && !running && !driverActive &&
        !proxy_thread && !udp_relay_thread && !cleanup_thread && !g_cleanup_stop &&
        !g_runtime_module && !g_update_guard && udp_relay_socket == INVALID_SOCKET &&
        udp_relay_socket6 == INVALID_SOCKET && test_tcp_clean();
}
__declspec(dllexport) int run_lifecycle_tests(void)
{
    // No configured rules, DNS flush or driver capture. TCP binds ephemeral ports.
    g_local_relay_port=0;
    CHECK(!ProxyBridge_Stop() && GetLastError()==ERROR_BUSY);
    for (int cycle=0; cycle<3; cycle++) {
        failDriver=TRUE;
        CHECK(!ProxyBridge_Start()); CHECK(stopped_clean());
        failDriver=FALSE;
        CHECK(ProxyBridge_Start()); CHECK(ProxyBridge_IsFilteringActive());
        CHECK(!ProxyBridge_Start() && GetLastError()==ERROR_BUSY);
        CHECK(ProxyBridge_Stop()); CHECK(stopped_clean());
        CHECK(!ProxyBridge_Stop() && GetLastError()==ERROR_BUSY);
    }
    puts("PASS Core lifecycle: 3 driver-start failures and 3 recoveries, real listeners/workers, duplicate Start/Stop");
    // Keep test-owned peer sockets alive across Core's own WSACleanup.
    WSADATA peerWsa; CHECK(!WSAStartup(MAKEWORD(2,2),&peerWsa));
    CHECK(!test_worker_reentry()); CHECK(stopped_clean());
    CHECK(!test_handshake_stop(FALSE,FALSE)); CHECK(stopped_clean());
    CHECK(!test_handshake_stop(TRUE,FALSE)); CHECK(stopped_clean());
    CHECK(!test_handshake_stop(FALSE,TRUE)); CHECK(stopped_clean());
    CHECK(!test_handshake_stop(TRUE,TRUE)); CHECK(stopped_clean());
    WSACleanup();
    return 0;
}

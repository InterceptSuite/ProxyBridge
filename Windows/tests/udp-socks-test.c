#include "pb_internal.h"
#include "../src/proxy/pb_udp_setup.inc"
#include "../src/relay/pb_udp_send.inc"

volatile BOOL running = TRUE;
LogCallback g_log_callback = NULL;

typedef struct {
    SOCKET listener;
    HANDLE stop;
    BOOL ok;
    BOOL authenticate;
    BOOL reject;
} SOCKS_FIXTURE;

static DWORD WINAPI socks_fixture(LPVOID argument)
{
    SOCKS_FIXTURE *fixture = argument;
    SOCKET control = INVALID_SOCKET, udp = INVALID_SOCKET;
    WSAPOLLFD accept_poll = {fixture->listener, POLLRDNORM, 0};
    if (WSAPoll(&accept_poll, 1, 3000) <= 0) goto done;
    control = accept(fixture->listener, NULL, NULL);
    if (control == INVALID_SOCKET) goto done;
    DWORD timeout = 3000;
    setsockopt(control, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(control, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
    unsigned char greeting[4], request[10];
    if (recv_n(control, (char *)greeting, 2) != 2 || greeting[0] != 5 ||
        greeting[1] != (fixture->authenticate ? 2 : 1)) goto done;
    if (recv_n(control, (char *)greeting + 2, greeting[1]) != greeting[1] || greeting[2] != 0) goto done;
    if (fixture->reject) {
        fixture->ok = send_all(control, "\x05\xff", 2) == 2;
        WaitForSingleObject(fixture->stop, 3000);
        goto done;
    }
    if (send_all(control, fixture->authenticate ? "\x05\x02" : "\x05\x00", 2) != 2) goto done;
    if (fixture->authenticate) {
        unsigned char auth[5];
        if (greeting[3] != 2 || recv_n(control, (char *)auth, 5) != 5 ||
            memcmp(auth, "\x01\x01" "u" "\x01" "p", 5)) goto done;
        if (send_all(control, "\x01\x00", 2) != 2) goto done;
    }
    if (recv_n(control, (char *)request, 10) != 10 || memcmp(request, "\x05\x03\x00\x01", 4)) goto done;
    udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) goto done;
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int address_length = sizeof(address);
    if (bind(udp, (struct sockaddr *)&address, sizeof(address)) ||
        getsockname(udp, (struct sockaddr *)&address, &address_length)) goto done;
    unsigned char reply[10] = {5, 0, 0, 1};
    memcpy(reply + 4, &address.sin_addr, 4);
    memcpy(reply + 8, &address.sin_port, 2);
    // Split header/address writes; receiver must tolerate any TCP segmentation.
    if (send_all(control, (char *)reply, 4) != 4 || send_all(control, (char *)reply + 4, 6) != 6) goto done;
    for (unsigned i = 0; i < PB_UDP_QUEUE_PACKETS; ++i) {
        unsigned char packet[32];
        struct sockaddr_in sender;
        int sender_length = sizeof(sender);
        int received = recvfrom(udp, (char *)packet, sizeof(packet), 0, (struct sockaddr *)&sender, &sender_length);
        if (received != 11 || memcmp(packet, "\0\0\0\x01\x01\x02\x03\x04\x01\xbb", 10) || packet[10] != i) goto done;
        if (sendto(udp, (char *)packet, received, 0, (struct sockaddr *)&sender, sender_length) != received) goto done;
    }
    fixture->ok = TRUE;
    WaitForSingleObject(fixture->stop, 3000);
done:
    if (udp != INVALID_SOCKET) closesocket(udp);
    if (control != INVALID_SOCKET) closesocket(control);
    return fixture->ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    PB_UDP_QUEUE_BUDGET budget = {0};
    PB_UDP_ASSOCIATION a = {0};
    a.pending.budget = &budget;
    a.udp_tcp_ctrl = a.udp_send_sock = INVALID_SOCKET;
    SOCKS_FIXTURE fixture = {INVALID_SOCKET, NULL, FALSE, FALSE, FALSE};
    fixture.authenticate = argc == 2 && strcmp(argv[1], "--auth") == 0;
    fixture.reject = argc == 2 && strcmp(argv[1], "--reject") == 0;
    HANDLE thread = NULL;
    BOOL ok = FALSE;
    fixture.stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    fixture.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!fixture.stop || fixture.listener == INVALID_SOCKET) goto done;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int address_length = sizeof(address);
    if (bind(fixture.listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(fixture.listener, 1) || getsockname(fixture.listener, (struct sockaddr *)&address, &address_length)) goto done;
    thread = CreateThread(NULL, 0, socks_fixture, &fixture, 0, NULL);
    if (!thread) goto done;
    a.config.type = PROXY_TYPE_SOCKS5;
    a.config.resolved_ip = address.sin_addr.s_addr;
    a.config.port = ntohs(address.sin_port);
    if (fixture.authenticate) { strcpy_s(a.config.username, sizeof(a.config.username), "u"); strcpy_s(a.config.password, sizeof(a.config.password), "p"); }
    for (unsigned i = 0; i < PB_UDP_QUEUE_PACKETS; ++i) {
        unsigned char packet[11] = {0, 0, 0, 1, 1, 2, 3, 4, 1, 187, (unsigned char)i};
        udp_send_payload(&a, packet, sizeof(packet));
    }
    if (a.pending.packets != PB_UDP_QUEUE_PACKETS) goto done;
    ULONGLONG deadline = GetTickCount64() + 5000;
    establish_udp_associate(&a);
    while (!a.udp_connected && GetTickCount64() < deadline) {
        short events = pb_udp_setup_events(&a);
        if (!events || a.udp_tcp_ctrl == INVALID_SOCKET) goto done;
        WSAPOLLFD poll = {a.udp_tcp_ctrl, events, 0};
        if (WSAPoll(&poll, 1, 2000) <= 0 || (poll.revents & (POLLERR | POLLHUP | POLLNVAL))) goto done;
        establish_udp_associate(&a);
        if (fixture.reject && a.setup_phase == UDP_IDLE && !a.pending.head && budget.bytes == 0) {
            ok = TRUE;
            goto done;
        }
    }
    if (!a.udp_connected || pb_udp_setup_events(&a) != 0) goto done;
    udp_flush_pending(&a);
    if (a.pending.head || budget.bytes != 0) goto done;
    for (unsigned i = 0; i < PB_UDP_QUEUE_PACKETS; ++i) {
        WSAPOLLFD poll = {a.udp_send_sock, POLLRDNORM, 0};
        if (WSAPoll(&poll, 1, 2000) <= 0) goto done;
        unsigned char packet[32];
        int received = recvfrom(a.udp_send_sock, (char *)packet, sizeof(packet), 0, NULL, NULL);
        if (received != 11 || packet[10] != i) goto done;
    }
    ok = TRUE;
done:
    pb_udp_association_close(&a);
    if (fixture.stop) SetEvent(fixture.stop);
    if (thread) {
        if (WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(thread);
        ok = ok && fixture.ok;
    }
    if (fixture.listener != INVALID_SOCKET) closesocket(fixture.listener);
    if (fixture.stop) CloseHandle(fixture.stop);
    WSACleanup();
    ok = ok && budget.bytes == 0;
    puts(ok ? (fixture.reject ? "PASS: SOCKS rejection clears queued burst" : "PASS: real SOCKS5 readiness handshake, queued 8-packet UDP burst/echo, teardown") : "FAIL: SOCKS5/UDP fixture");
    return ok ? 0 : 1;
}

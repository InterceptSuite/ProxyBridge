// TLS ClientHello SNI extraction.
//
// The DNS sources can only name a connection when the application resolved the name while
// ProxyBridge was watching: an app that answers from its own cache (Chromium and other
// long-lived Electron apps cache well beyond the system resolver cache) never shows up on
// the wire and never produces a DNS Client event that carries results. The ClientHello of a
// TLS connection always carries the name the application actually wants, and it arrives on
// the relay's app-side socket a few hundred microseconds after the SYN - so SNI is the one
// source that covers every TLS connection regardless of how the name was resolved.
//
// The socket is only ever PEEKED, so the bytes stay in the receive queue for the relay.

#include "pb_internal.h"

// Bound both socket peeking and the handshake reassembly buffer.
#define SNI_MAX_HELLO 4096
#define SNI_PEEK_WINDOW_MS 50
#define SNI_NO_PROGRESS_MS 10
// shortcut: stop after 10 ms without more ClientHello bytes; increase if slow handshakes need better name recovery.

static UINT32 sni_read_u16(const UINT8 *p)
{
    return ((UINT32)p[0] << 8) | (UINT32)p[1];
}

static UINT32 sni_read_u24(const UINT8 *p)
{
    return ((UINT32)p[0] << 16) | ((UINT32)p[1] << 8) | (UINT32)p[2];
}

// A hostname taken out of a TLS ClientHello must look like one, otherwise an arbitrary byte
// sequence that merely starts with 0x16 could be published as a name.
static BOOL sni_name_plausible(const char *name, size_t length)
{
    size_t label = 0;
    BOOL dot = FALSE;
    if (length == 0 || length > 253) return FALSE;
    for (size_t i = 0; i < length; i++)
    {
        unsigned char c = (unsigned char)name[i];
        if (c == '.')
        {
            if (label == 0 || label > 63) return FALSE;
            label = 0;
            dot = TRUE;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_'))
            return FALSE;
        label++;
    }
    return dot && label > 0 && label <= 63;
}

static SNI_RESULT sni_parse_handshake(const UINT8 *handshake, size_t length,
                                      char *out, size_t out_size)
{
    if (length < 4) return SNI_NEED_MORE;
    if (handshake[0] != 0x01) return SNI_NOT_TLS;
    size_t hello_end = 4 + (size_t)sni_read_u24(handshake + 1);
    if (hello_end <= 4 || hello_end > SNI_MAX_HELLO) return SNI_NOT_TLS;
    if (hello_end > length) return SNI_NEED_MORE;

    size_t pos = 4 + 2 + 32;                       // legacy_version + random
    if (pos + 1 > hello_end) return SNI_NOT_TLS;
    size_t session_len = handshake[pos];
    pos += 1 + session_len;
    if (pos + 2 > hello_end) return SNI_NOT_TLS;
    size_t cipher_len = sni_read_u16(handshake + pos);
    pos += 2 + cipher_len;
    if (pos + 1 > hello_end) return SNI_NOT_TLS;
    size_t compression_len = handshake[pos];
    pos += 1 + compression_len;
    if (pos + 2 > hello_end) return SNI_NOT_TLS;   // no extensions (or truncated)

    size_t extensions_end = pos + 2 + (size_t)sni_read_u16(handshake + pos);
    pos += 2;
    if (extensions_end > hello_end) return SNI_NOT_TLS;

    while (pos + 4 <= extensions_end)
    {
        UINT32 type = sni_read_u16(handshake + pos);
        UINT32 size = sni_read_u16(handshake + pos + 2);
        pos += 4;
        if (pos + size > extensions_end) return SNI_NOT_TLS;

        if (type != 0x0000) { pos += size; continue; }

        if (size < 3) return SNI_NOT_TLS;
        size_t list_end = pos + size;
        size_t cursor = pos + 2;                   // skip server_name_list length
        while (cursor + 3 <= list_end)
        {
            UINT32 name_type = handshake[cursor];
            UINT32 name_len = sni_read_u16(handshake + cursor + 1);
            cursor += 3;
            if (cursor + name_len > list_end) return SNI_NOT_TLS;
            if (name_type == 0 && name_len > 0)
            {
                if (name_len >= out_size || name_len > 253) return SNI_NOT_TLS;
                for (UINT32 i = 0; i < name_len; i++)
                {
                    unsigned char c = handshake[cursor + i];
                    out[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
                }
                out[name_len] = '\0';
                return sni_name_plausible(out, name_len) ? SNI_FOUND : SNI_NOT_TLS;
            }
            cursor += name_len;
        }
        return SNI_NOT_TLS;
    }
    return SNI_NOT_TLS;
}

// Reassemble the first handshake message from one or more TLS handshake records.
// NEED_MORE means the socket peek may still contain a valid partial ClientHello.
SNI_RESULT sni_parse_client_hello(const UINT8 *data, size_t length, char *out, size_t out_size)
{
    if (!data || !out || out_size < 4) return SNI_NOT_TLS;
    out[0] = '\0';
    if (length == 0) return SNI_NEED_MORE;
    if (data[0] != 0x16) return SNI_NOT_TLS;

    UINT8 handshake[SNI_MAX_HELLO];
    size_t handshake_length = 0;
    size_t offset = 0;
    for (;;)
    {
        if (length - offset < 5) return SNI_NEED_MORE;
        if (data[offset] != 0x16 || data[offset + 1] != 0x03)
            return SNI_NOT_TLS;

        size_t record_length = sni_read_u16(data + offset + 3);
        if (record_length == 0 || record_length > 18432) return SNI_NOT_TLS;
        offset += 5;

        size_t available = length - offset;
        size_t take = available < record_length ? available : record_length;
        size_t remaining = sizeof(handshake) - handshake_length;
        if (take > remaining) take = remaining;
        if (take)
        {
            memcpy(handshake + handshake_length, data + offset, take);
            handshake_length += take;
        }

        if (handshake_length && handshake[0] != 0x01) return SNI_NOT_TLS;
        if (handshake_length >= 4)
        {
            size_t hello_end = 4 + (size_t)sni_read_u24(handshake + 1);
            if (hello_end <= 4 || hello_end > sizeof(handshake)) return SNI_NOT_TLS;
            if (handshake_length >= hello_end)
                return sni_parse_handshake(handshake, hello_end, out, out_size);
        }

        if (available < record_length) return SNI_NEED_MORE;
        offset += record_length;
        if (offset == length) return SNI_NEED_MORE;
        if (handshake_length == sizeof(handshake)) return SNI_NOT_TLS;
    }
}

// Read (without consuming) the client's ClientHello and return its SNI, if any. Returns
// quickly: it stops as soon as the buffered bytes are clearly not a TLS ClientHello, so a
// plain-HTTP or server-speaks-first protocol only pays a few microseconds.
BOOL sni_peek_from_socket(SOCKET sock, char *out, size_t out_size)
{
    UINT8 buffer[SNI_MAX_HELLO];
    ULONGLONG deadline = GetTickCount64() + SNI_PEEK_WINDOW_MS;
    ULONGLONG last_progress = 0;
    int previous_got = -1;

    for (;;)
    {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(sock, &readable);

        ULONGLONG now = GetTickCount64();
        if (now >= deadline) return FALSE;
        DWORD remaining = (DWORD)(deadline - now);
        struct timeval tv;
        tv.tv_sec = (long)(remaining / 1000);
        tv.tv_usec = (long)((remaining % 1000) * 1000);
        if (select(0, &readable, NULL, NULL, &tv) <= 0) return FALSE;

        int got = recv(sock, (char *)buffer, (int)sizeof(buffer), MSG_PEEK);
        if (got <= 0) return FALSE;

        now = GetTickCount64();
        if (got != previous_got)
        {
            previous_got = got;
            last_progress = now;
        }
        else if (now - last_progress >= SNI_NO_PROGRESS_MS)
        {
            return FALSE;
        }

        SNI_RESULT result = sni_parse_client_hello(buffer, (size_t)got, out, out_size);
        if (result == SNI_FOUND) return TRUE;
        if (result == SNI_NOT_TLS) return FALSE;
        if ((size_t)got == sizeof(buffer)) return FALSE;
        Sleep(1);   // truncated ClientHello: wait for the rest of the bytes
    }
}

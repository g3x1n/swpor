/*
 * 平台抽象层：套接字 Windows 实现（Winsock2）。见 SPEC 2.1、8.1、8.4。
 * Windows 只做客户端：listen / accept 返回 SWPOR_E_UNSUPPORTED。
 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "swpor/error.h"

struct swpor_sock {
    SOCKET fd;
};

int swpor_sock_listen(const char *host, uint16_t port, int backlog, swpor_sock_t **out)
{
    (void)host;
    (void)port;
    (void)backlog;
    (void)out;
    return SWPOR_E_UNSUPPORTED;
}

int swpor_sock_accept(swpor_sock_t *ls, swpor_sock_t **out)
{
    (void)ls;
    (void)out;
    return SWPOR_E_UNSUPPORTED;
}

int swpor_sock_connect(const char *host, uint16_t port, swpor_sock_t **out)
{
    if (host == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    (void)snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return SWPOR_E_NET;
    }
    int rc = SWPOR_E_NET;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        SOCKET fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == INVALID_SOCKET) {
            continue;
        }
        if (connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            swpor_sock_t *s = malloc(sizeof(*s));
            if (s == NULL) {
                closesocket(fd);
                rc = SWPOR_E_NOMEM;
                break;
            }
            BOOL one = TRUE;
            (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
            s->fd = fd;
            *out = s;
            rc = SWPOR_OK;
            break;
        }
        closesocket(fd);
    }
    freeaddrinfo(res);
    return rc;
}

int swpor_sock_set_timeout(swpor_sock_t *s, uint32_t ms)
{
    if (s == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    /* Windows：毫秒数 DWORD（SPEC 8.4） */
    DWORD v = (DWORD)ms;
    if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&v, sizeof(v)) != 0 ||
        setsockopt(s->fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&v, sizeof(v)) != 0) {
        return SWPOR_E_NET;
    }
    return SWPOR_OK;
}

int swpor_sock_send_all(swpor_sock_t *s, const void *buf, size_t len)
{
    if (s == NULL || (buf == NULL && len > 0)) {
        return SWPOR_E_INVALID_ARG;
    }
    const char *p = buf;
    while (len > 0) {
        int chunk = len > 0x40000000u ? 0x40000000 : (int)len;
        int r = send(s->fd, p, chunk, 0);
        if (r == SOCKET_ERROR) {
            return WSAGetLastError() == WSAETIMEDOUT ? SWPOR_E_TIMEOUT : SWPOR_E_NET;
        }
        p += r;
        len -= (size_t)r;
    }
    return SWPOR_OK;
}

int swpor_sock_recv_all(swpor_sock_t *s, void *buf, size_t len)
{
    if (s == NULL || (buf == NULL && len > 0)) {
        return SWPOR_E_INVALID_ARG;
    }
    char *p = buf;
    while (len > 0) {
        int chunk = len > 0x40000000u ? 0x40000000 : (int)len;
        int r = recv(s->fd, p, chunk, 0);
        if (r == SOCKET_ERROR) {
            return WSAGetLastError() == WSAETIMEDOUT ? SWPOR_E_TIMEOUT : SWPOR_E_NET;
        }
        if (r == 0) {
            return SWPOR_E_NET;
        }
        p += r;
        len -= (size_t)r;
    }
    return SWPOR_OK;
}

void swpor_sock_shutdown_write(swpor_sock_t *s)
{
    if (s != NULL) {
        (void)shutdown(s->fd, SD_SEND);
    }
}

int swpor_sock_local_port(swpor_sock_t *s, uint16_t *port)
{
    if (s == NULL || port == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    struct sockaddr_in sa;
    int len = sizeof(sa);
    if (getsockname(s->fd, (struct sockaddr *)&sa, &len) != 0) {
        return SWPOR_E_NET;
    }
    *port = ntohs(sa.sin_port);
    return SWPOR_OK;
}

void swpor_sock_close(swpor_sock_t *s)
{
    if (s == NULL) {
        return;
    }
    closesocket(s->fd);
    free(s);
}

#else
typedef int swpor_sock_win32_unused;
#endif /* _WIN32 */

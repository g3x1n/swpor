/* 平台抽象层：套接字 POSIX 实现（macOS、Linux）。见 SPEC 8.1、8.4。 */

#if !defined(_WIN32)

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#else
#define _GNU_SOURCE 1
#endif

#include "platform.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "swpor/error.h"

#if defined(MSG_NOSIGNAL)
#define SWPOR_SEND_FLAGS MSG_NOSIGNAL
#else
#define SWPOR_SEND_FLAGS 0
#endif

struct swpor_sock {
    int fd;
};

static int wrap(int fd, swpor_sock_t **out)
{
    swpor_sock_t *s = malloc(sizeof(*s));
    if (s == NULL) {
        close(fd);
        return SWPOR_E_NOMEM;
    }
#if defined(SO_NOSIGPIPE)
    /* macOS 没有 MSG_NOSIGNAL：对端关闭时避免 SIGPIPE */
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    s->fd = fd;
    *out = s;
    return SWPOR_OK;
}

int swpor_sock_listen(const char *host, uint16_t port, int backlog, swpor_sock_t **out)
{
    if (out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char portstr[8];
    (void)snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    const char *h = (host == NULL || host[0] == '\0' || strcmp(host, "0.0.0.0") == 0) ? NULL : host;
    if (getaddrinfo(h, portstr, &hints, &res) != 0 || res == NULL) {
        return SWPOR_E_NET;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return SWPOR_E_NET;
    }
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, res->ai_addr, res->ai_addrlen) != 0 || listen(fd, backlog) != 0) {
        freeaddrinfo(res);
        close(fd);
        return SWPOR_E_NET;
    }
    freeaddrinfo(res);
    return wrap(fd, out);
}

int swpor_sock_accept(swpor_sock_t *ls, swpor_sock_t **out)
{
    if (ls == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    for (;;) {
        int fd = accept(ls->fd, NULL, NULL);
        if (fd >= 0) {
            int one = 1;
            (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            return wrap(fd, out);
        }
        if (errno != EINTR) {
            return SWPOR_E_NET;
        }
    }
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
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            int one = 1;
            (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            rc = wrap(fd, out);
            break;
        }
        close(fd);
    }
    freeaddrinfo(res);
    return rc;
}

int swpor_sock_set_timeout(swpor_sock_t *s, uint32_t ms)
{
    if (s == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    /* POSIX：struct timeval（SPEC 8.4） */
    struct timeval tv;
    tv.tv_sec = (time_t)(ms / 1000u);
    tv.tv_usec = (suseconds_t)((ms % 1000u) * 1000u);
    if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
        setsockopt(s->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        return SWPOR_E_NET;
    }
    return SWPOR_OK;
}

int swpor_sock_send_all(swpor_sock_t *s, const void *buf, size_t len)
{
    if (s == NULL || (buf == NULL && len > 0)) {
        return SWPOR_E_INVALID_ARG;
    }
    const uint8_t *p = buf;
    while (len > 0) {
        int64_t r = (int64_t)send(s->fd, p, len, SWPOR_SEND_FLAGS);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return (errno == EAGAIN || errno == EWOULDBLOCK) ? SWPOR_E_TIMEOUT : SWPOR_E_NET;
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
    uint8_t *p = buf;
    while (len > 0) {
        int64_t r = (int64_t)recv(s->fd, p, len, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return (errno == EAGAIN || errno == EWOULDBLOCK) ? SWPOR_E_TIMEOUT : SWPOR_E_NET;
        }
        if (r == 0) {
            return SWPOR_E_NET; /* 对端关闭 */
        }
        p += r;
        len -= (size_t)r;
    }
    return SWPOR_OK;
}

void swpor_sock_shutdown_write(swpor_sock_t *s)
{
    if (s != NULL) {
        (void)shutdown(s->fd, SHUT_WR);
    }
}

int swpor_sock_local_port(swpor_sock_t *s, uint16_t *port)
{
    if (s == NULL || port == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
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
    close(s->fd);
    free(s);
}

#else
typedef int swpor_sock_posix_unused;
#endif /* !_WIN32 */

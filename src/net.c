/* See include/common.h for license and attribution. */
#define _POSIX_C_SOURCE 200112L
#include "net.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/* ---------- plain fd ---------- */
struct fdio {
    int fd;
};

static long fd_read(void *c, uint8_t *b, size_t n)
{
    ssize_t r;
    do {
        r = recv(((struct fdio *)c)->fd, b, n, 0);
    } while (r < 0 && errno == EINTR);
    if (r < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? CM_IO_AGAIN : CM_IO_FAIL;
    return (long)r;
}

static long fd_write(void *c, const uint8_t *b, size_t n)
{
    ssize_t r;
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    do {
        r = send(((struct fdio *)c)->fd, b, n, flags);
    } while (r < 0 && errno == EINTR);
    if (r < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? CM_IO_AGAIN : CM_IO_FAIL;
    return (long)r;
}

static int fd_fd(void *c) { return ((struct fdio *)c)->fd; }
static int fd_pending(void *c) { (void)c; return 0; }

static void fd_close(void *c)
{
    close(((struct fdio *)c)->fd);
    free(c);
}

static const cm_io_ops fd_ops = {fd_read, fd_write, fd_fd, fd_pending, fd_close};

static int set_nonblock(int fd, int on)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return -1;
    return fcntl(fd, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
}

cm_io cm_io_from_fd(int fd)
{
    cm_io io;
    struct fdio *f = (struct fdio *)malloc(sizeof(*f));

    io.ops = NULL;
    io.ctx = NULL;
    if (f == NULL)
        return io;
    f->fd = fd;
    set_nonblock(fd, 1);
    io.ops = &fd_ops;
    io.ctx = f;
    return io;
}

void cm_io_close(cm_io *io)
{
    if (io->ops != NULL)
        io->ops->close(io->ctx);
    io->ops = NULL;
    io->ctx = NULL;
}

static int wait_fd(int fd, int want_write, int timeout_ms)
{
    struct pollfd p;
    int r;

    p.fd = fd;
    p.events = want_write ? POLLOUT : POLLIN;
    p.revents = 0;
    do {
        r = poll(&p, 1, timeout_ms);
    } while (r < 0 && errno == EINTR);
    if (r < 0)
        return -1;
    return r > 0 ? 1 : 0;
}

int cm_io_wait(const cm_io *io, int want_write, int timeout_ms)
{
    if (!want_write && io->ops->pending(io->ctx))
        return 1;
    return wait_fd(io->ops->fd(io->ctx), want_write, timeout_ms);
}

static cm_err tcp_connect_fd(int *out, const char *host, const char *port, int timeout_ms)
{
    struct addrinfo hints, *res, *ai;
    cm_err result = CM_ERR_IO;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return CM_ERR_IO;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        int w, soerr = 0;
        socklen_t sl = sizeof(soerr);

        if (fd < 0)
            continue;
        set_nonblock(fd, 1);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0 && errno != EINPROGRESS) {
            close(fd);
            continue;
        }
        w = wait_fd(fd, 1, timeout_ms);
        if (w == 0) {
            result = CM_ERR_TIMEOUT;
            close(fd);
            continue;
        }
        if (w < 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
            close(fd);
            continue;
        }
        *out = fd;
        result = CM_OK;
        break;
    }
    freeaddrinfo(res);
    return result;
}

cm_err cm_io_tcp_connect(cm_io *io, const char *host, const char *port, int timeout_ms)
{
    int fd;
    cm_err e = tcp_connect_fd(&fd, host, port, timeout_ms);

    if (e != CM_OK)
        return e;
    *io = cm_io_from_fd(fd);
    if (io->ops == NULL) {
        close(fd);
        return CM_ERR_NOMEM;
    }
    return CM_OK;
}

/* ---------- TLS ---------- */
struct tlsio {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;
};

static long tls_result(struct tlsio *t, int r)
{
    int e = SSL_get_error(t->ssl, r);

    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
        return CM_IO_AGAIN;
    if (e == SSL_ERROR_ZERO_RETURN)
        return 0;
    ERR_clear_error();
    return CM_IO_FAIL;
}

static long tls_read(void *c, uint8_t *b, size_t n)
{
    struct tlsio *t = (struct tlsio *)c;
    int r;

    if (n > 0x7fffffff)
        n = 0x7fffffff;
    r = SSL_read(t->ssl, b, (int)n);
    return r > 0 ? r : tls_result(t, r);
}

static long tls_write(void *c, const uint8_t *b, size_t n)
{
    struct tlsio *t = (struct tlsio *)c;
    int r;

    if (n > 0x7fffffff)
        n = 0x7fffffff;
    r = SSL_write(t->ssl, b, (int)n);
    return r > 0 ? r : tls_result(t, r);
}

static int tls_fd(void *c) { return ((struct tlsio *)c)->fd; }
static int tls_pending(void *c) { return SSL_pending(((struct tlsio *)c)->ssl) > 0; }

static void tls_close(void *c)
{
    struct tlsio *t = (struct tlsio *)c;

    if (t->ssl != NULL) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
    }
    if (t->ctx != NULL)
        SSL_CTX_free(t->ctx);
    if (t->fd >= 0)
        close(t->fd);
    free(t);
}

static const cm_io_ops tls_ops = {tls_read, tls_write, tls_fd, tls_pending, tls_close};

cm_err cm_io_tls_connect(cm_io *io, const char *host, const char *port, const char *ca_file,
                         int timeout_ms)
{
    struct tlsio *t;
    cm_err e;

    t = (struct tlsio *)calloc(1, sizeof(*t));
    if (t == NULL)
        return CM_ERR_NOMEM;
    t->fd = -1;
    e = tcp_connect_fd(&t->fd, host, port, timeout_ms);
    if (e != CM_OK)
        goto fail;
    e = CM_ERR_CRYPTO;
    t->ctx = SSL_CTX_new(TLS_client_method());
    if (t->ctx == NULL)
        goto fail;
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);
    if (ca_file != NULL) {
        if (SSL_CTX_load_verify_locations(t->ctx, ca_file, NULL) != 1)
            goto fail;
    } else if (SSL_CTX_set_default_verify_paths(t->ctx) != 1) {
        goto fail;
    }
    t->ssl = SSL_new(t->ctx);
    if (t->ssl == NULL)
        goto fail;
    SSL_set_fd(t->ssl, t->fd);
    SSL_set_tlsext_host_name(t->ssl, host);
    if (SSL_set1_host(t->ssl, host) != 1)
        goto fail;
    for (;;) {
        int r = SSL_connect(t->ssl);
        int err, w;

        if (r == 1)
            break;
        err = SSL_get_error(t->ssl, r);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            e = CM_ERR_AUTH;
            goto fail;
        }
        w = wait_fd(t->fd, err == SSL_ERROR_WANT_WRITE, timeout_ms);
        if (w <= 0) {
            e = w == 0 ? CM_ERR_TIMEOUT : CM_ERR_IO;
            goto fail;
        }
    }
    io->ops = &tls_ops;
    io->ctx = t;
    return CM_OK;
fail:
    ERR_clear_error();
    tls_close(t);
    return e;
}

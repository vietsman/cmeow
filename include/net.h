/* See include/common.h for license and attribution. */
#ifndef CMEOW_NET_H
#define CMEOW_NET_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Byte-stream transport abstraction (replaces Go's net.Conn). Whatever sits
 * below the websocket - TLS over TCP in production, a plain socket in tests,
 * or something platform specific - implements these ops.
 *
 * read/write return: >0 bytes transferred, 0 = orderly EOF (read only),
 * CM_IO_AGAIN = would block (retry when fd is ready), CM_IO_FAIL = error.
 */
#define CM_IO_AGAIN (-1L)
#define CM_IO_FAIL (-2L)

typedef struct cm_io_ops {
    long (*read)(void *ctx, uint8_t *buf, size_t n);
    long (*write)(void *ctx, const uint8_t *buf, size_t n);
    int (*fd)(void *ctx);       /* descriptor to poll() */
    int (*pending)(void *ctx);  /* decrypted bytes already buffered (TLS) */
    void (*close)(void *ctx);   /* closes and frees ctx */
} cm_io_ops;

typedef struct cm_io {
    const cm_io_ops *ops;
    void *ctx;
} cm_io;

/* Plain TCP (tests / local proxies). Connected and set non-blocking. */
cm_err cm_io_tcp_connect(cm_io *io, const char *host, const char *port, int timeout_ms);

/*
 * TLS over TCP using the statically linked OpenSSL. Verifies the certificate
 * chain and host name. ca_file may be NULL to use OpenSSL's default store.
 */
cm_err cm_io_tls_connect(cm_io *io, const char *host, const char *port, const char *ca_file,
                         int timeout_ms);

/* Wrap an already-connected socket descriptor (takes ownership; sets non-blocking). */
cm_io cm_io_from_fd(int fd);

void cm_io_close(cm_io *io);

/* Wait until the io is readable (or writable). 1 = ready, 0 = timeout, -1 = error. */
int cm_io_wait(const cm_io *io, int want_write, int timeout_ms);

#ifdef __cplusplus
}
#endif
#endif

/* See include/common.h for license and attribution.
 * Minimal blocking HTTP/1.1 client over cm_io (used for WhatsApp media servers). */
#ifndef CMEOW_HTTP_H
#define CMEOW_HTTP_H

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Request body producer: fill up to n bytes, return bytes written, 0 at end, <0 on error. */
typedef long (*cm_http_read_cb)(void *ud, uint8_t *buf, size_t n);
/* Response body consumer; called once per chunk (status is the HTTP status). Return 0 to continue. */
typedef int (*cm_http_body_cb)(void *ud, int status, const uint8_t *p, size_t n);

typedef struct cm_http_req {
    const char *method;              /* "GET", "POST", "DELETE" */
    const char *url;                 /* http:// or https:// */
    const char *const *headers;      /* "Name: value" strings */
    size_t nheaders;
    const uint8_t *body;             /* in-memory body, or NULL */
    uint64_t body_len;               /* total body length (also for body_read) */
    cm_http_read_cb body_read;       /* streaming body (used when body == NULL and body_len > 0) */
    void *body_ud;
} cm_http_req;

typedef struct cm_http_opts {
    const char *ca_file;  /* PEM bundle for TLS (NULL = default store) */
    int timeout_ms;       /* connect and per-I/O timeout (default 30000) */
} cm_http_opts;

typedef struct cm_http_resp {
    int status;
    int64_t content_length; /* -1 if unknown */
    int retry_after;        /* seconds, 0 if absent */
} cm_http_resp;

/* Performs the request; redirects are not followed. Any status is CM_OK; I/O problems give
 * CM_ERR_IO / CM_ERR_TIMEOUT / CM_ERR_PROTO. */
cm_err cm_http_do(const cm_http_req *req, const cm_http_opts *opts, cm_http_resp *resp,
                  cm_http_body_cb on_body, void *ud);

/* Percent-encodes everything but RFC 3986 unreserved characters. Returns malloc()ed. */
char *cm_url_escape(const char *s);

#ifdef __cplusplus
}
#endif
#endif

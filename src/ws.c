/* See include/common.h for license and attribution. */
#include "ws.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <wslay/wslay.h>

#include "buf.h"
#include "crypto.h"
#include "noise.h" /* CM_FRAME_MAX_SIZE */

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_HEADERS 16384

struct cm_ws {
    cm_io io;
    wslay_event_context_ptr ev;
    uint8_t *pre; /* bytes read past the HTTP response */
    size_t pre_len, pre_off;
    cm_ws_msg_cb cb;
    void *user;
    cm_err cb_err;
    int closed, failed;
};

cm_err cm_ws_accept_key(const char *key, char out[29])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdl = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t kl = strlen(key);
    int ok;

    if (c == NULL)
        return CM_ERR_NOMEM;
    ok = EVP_DigestInit_ex(c, EVP_sha1(), NULL) == 1 && EVP_DigestUpdate(c, key, kl) == 1 &&
         EVP_DigestUpdate(c, WS_GUID, strlen(WS_GUID)) == 1 && EVP_DigestFinal_ex(c, md, &mdl) == 1;
    EVP_MD_CTX_free(c);
    if (!ok || mdl != 20)
        return CM_ERR_CRYPTO;
    EVP_EncodeBlock((unsigned char *)out, md, 20);
    out[28] = '\0';
    return CM_OK;
}

static int ci_prefix(const char *s, const char *p)
{
    while (*p) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*p))
            return 0;
        s++;
        p++;
    }
    return 1;
}

/* ---- wslay callbacks ---- */
static ssize_t on_recv(wslay_event_context_ptr ev, uint8_t *buf, size_t len, int flags, void *u)
{
    cm_ws *ws = (cm_ws *)u;
    long r;

    (void)flags;
    if (ws->pre_off < ws->pre_len) {
        size_t n = ws->pre_len - ws->pre_off;

        if (n > len)
            n = len;
        memcpy(buf, ws->pre + ws->pre_off, n);
        ws->pre_off += n;
        return (ssize_t)n;
    }
    r = ws->io.ops->read(ws->io.ctx, buf, len);
    if (r > 0)
        return (ssize_t)r;
    if (r == CM_IO_AGAIN) {
        wslay_event_set_error(ev, WSLAY_ERR_WOULDBLOCK);
    } else {
        if (r == 0)
            ws->closed = 1;
        else
            ws->failed = 1;
        wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
    }
    return -1;
}

static ssize_t on_send(wslay_event_context_ptr ev, const uint8_t *data, size_t len, int flags,
                       void *u)
{
    cm_ws *ws = (cm_ws *)u;
    long r;

    (void)flags;
    r = ws->io.ops->write(ws->io.ctx, data, len);
    if (r > 0)
        return (ssize_t)r;
    if (r == CM_IO_AGAIN) {
        wslay_event_set_error(ev, WSLAY_ERR_WOULDBLOCK);
    } else {
        ws->failed = 1;
        wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
    }
    return -1;
}

static int on_genmask(wslay_event_context_ptr ev, uint8_t *buf, size_t len, void *u)
{
    (void)ev;
    (void)u;
    return cm_random(buf, len) == CM_OK ? 0 : -1;
}

static void on_msg(wslay_event_context_ptr ev, const struct wslay_event_on_msg_recv_arg *arg,
                   void *u)
{
    cm_ws *ws = (cm_ws *)u;

    (void)ev;
    if (arg->opcode == WSLAY_CONNECTION_CLOSE) {
        ws->closed = 1;
    } else if (arg->opcode == WSLAY_BINARY_FRAME && ws->cb_err == CM_OK) {
        ws->cb_err = ws->cb(ws->user, arg->msg, arg->msg_length);
    }
}

/* ---- HTTP upgrade ---- */
static cm_err write_all(cm_io *io, const uint8_t *p, size_t n, int timeout_ms)
{
    while (n > 0) {
        long r = io->ops->write(io->ctx, p, n);

        if (r > 0) {
            p += r;
            n -= (size_t)r;
        } else if (r == CM_IO_AGAIN) {
            int w = cm_io_wait(io, 1, timeout_ms);

            if (w == 0)
                return CM_ERR_TIMEOUT;
            if (w < 0)
                return CM_ERR_IO;
        } else {
            return CM_ERR_IO;
        }
    }
    return CM_OK;
}

static cm_err check_response(const char *hdr, const char *want_accept)
{
    const char *p = hdr, *eol;
    int got_accept = 0;

    if (strncmp(p, "HTTP/1.1 101", 12) != 0 && strncmp(p, "HTTP/1.0 101", 12) != 0)
        return CM_ERR_PROTO;
    for (;;) {
        eol = strstr(p, "\r\n");
        if (eol == NULL || eol == p)
            break;
        p = eol + 2;
        if (ci_prefix(p, "sec-websocket-accept:")) {
            const char *v = p + 21;
            size_t n = strlen(want_accept);

            while (*v == ' ' || *v == '\t')
                v++;
            if (strncmp(v, want_accept, n) != 0 || (v[n] != '\r' && v[n] != '\0'))
                return CM_ERR_AUTH;
            got_accept = 1;
        }
    }
    return got_accept ? CM_OK : CM_ERR_PROTO;
}

cm_err cm_ws_connect(cm_ws **out, cm_io *io, const char *host, const char *path,
                     const char *origin, int timeout_ms)
{
    uint8_t raw[16];
    char key[32], accept[29], req[1024], *resp, *end;
    size_t resp_len = 0, resp_cap = 1024;
    cm_ws *ws;
    struct wslay_event_callbacks cbs;
    cm_err e;
    int n;

    *out = NULL;
    e = cm_random(raw, sizeof(raw));
    if (e != CM_OK)
        return e;
    EVP_EncodeBlock((unsigned char *)key, raw, sizeof(raw));
    e = cm_ws_accept_key(key, accept);
    if (e != CM_OK)
        return e;
    n = snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n%s%s%s\r\n",
                 path, host, key, origin ? "Origin: " : "", origin ? origin : "",
                 origin ? "\r\n" : "");
    if (n <= 0 || (size_t)n >= sizeof(req))
        return CM_ERR_ARG;
    e = write_all(io, (const uint8_t *)req, (size_t)n, timeout_ms);
    if (e != CM_OK)
        return e;

    resp = (char *)malloc(resp_cap);
    if (resp == NULL)
        return CM_ERR_NOMEM;
    for (;;) {
        long r;

        resp[resp_len] = '\0';
        end = strstr(resp, "\r\n\r\n");
        if (end != NULL)
            break;
        if (resp_len + 1 >= resp_cap) {
            char *nb;

            if (resp_cap >= WS_MAX_HEADERS) {
                free(resp);
                return CM_ERR_TOO_LARGE;
            }
            resp_cap *= 2;
            nb = (char *)realloc(resp, resp_cap);
            if (nb == NULL) {
                free(resp);
                return CM_ERR_NOMEM;
            }
            resp = nb;
        }
        r = io->ops->read(io->ctx, (uint8_t *)resp + resp_len, resp_cap - resp_len - 1);
        if (r > 0) {
            resp_len += (size_t)r;
        } else if (r == CM_IO_AGAIN) {
            int w = cm_io_wait(io, 0, timeout_ms);

            if (w <= 0) {
                free(resp);
                return w == 0 ? CM_ERR_TIMEOUT : CM_ERR_IO;
            }
        } else {
            free(resp);
            return r == 0 ? CM_ERR_CLOSED : CM_ERR_IO;
        }
    }
    e = check_response(resp, accept);
    if (e != CM_OK) {
        free(resp);
        return e;
    }

    ws = (cm_ws *)calloc(1, sizeof(*ws));
    if (ws == NULL) {
        free(resp);
        return CM_ERR_NOMEM;
    }
    end += 4;
    ws->pre_len = resp_len - (size_t)(end - resp);
    if (ws->pre_len > 0) {
        ws->pre = (uint8_t *)cm_memdup(end, ws->pre_len);
        if (ws->pre == NULL) {
            free(resp);
            free(ws);
            return CM_ERR_NOMEM;
        }
    }
    free(resp);

    memset(&cbs, 0, sizeof(cbs));
    cbs.recv_callback = on_recv;
    cbs.send_callback = on_send;
    cbs.genmask_callback = on_genmask;
    cbs.on_msg_recv_callback = on_msg;
    if (wslay_event_context_client_init(&ws->ev, &cbs, ws) != 0) {
        free(ws->pre);
        free(ws);
        return CM_ERR_NOMEM;
    }
    wslay_event_config_set_max_recv_msg_length(ws->ev, CM_FRAME_MAX_SIZE + 64);
    ws->io = *io;
    io->ops = NULL;
    io->ctx = NULL;
    *out = ws;
    return CM_OK;
}

cm_err cm_ws_send(cm_ws *ws, const uint8_t *data, size_t len)
{
    struct wslay_event_msg m;

    m.opcode = WSLAY_BINARY_FRAME;
    m.msg = data;
    m.msg_length = len;
    return wslay_event_queue_msg(ws->ev, &m) == 0 ? CM_OK : CM_ERR_NOMEM;
}

void cm_ws_close(cm_ws *ws)
{
    wslay_event_queue_close(ws->ev, WSLAY_CODE_NORMAL_CLOSURE, NULL, 0);
}

static cm_err flush(cm_ws *ws)
{
    int r = wslay_event_send(ws->ev);

    if (r == WSLAY_ERR_NOMEM)
        return CM_ERR_NOMEM;
    if (r != 0 || ws->failed)
        return ws->closed ? CM_ERR_CLOSED : CM_ERR_IO;
    return CM_OK;
}

cm_err cm_ws_pump(cm_ws *ws, int timeout_ms, cm_ws_msg_cb cb, void *user)
{
    cm_err e;
    int w, r;

    ws->cb = cb;
    ws->user = user;
    ws->cb_err = CM_OK;

    e = flush(ws);
    if (e != CM_OK)
        return e;
    if (!wslay_event_want_read(ws->ev) && !wslay_event_want_write(ws->ev))
        return CM_ERR_CLOSED;

    if (ws->pre_off < ws->pre_len)
        w = 1;
    else
        w = cm_io_wait(&ws->io, wslay_event_want_write(ws->ev), timeout_ms);
    if (w < 0)
        return CM_ERR_IO;
    if (w == 0)
        return CM_ERR_TIMEOUT;

    if (wslay_event_want_write(ws->ev)) {
        e = flush(ws); /* socket became writable */
        return e;
    }
    r = wslay_event_recv(ws->ev);
    if (ws->cb_err != CM_OK)
        return ws->cb_err;
    if (r == WSLAY_ERR_NOMEM)
        return CM_ERR_NOMEM;
    if (r != 0) {
        if (ws->closed)
            return CM_ERR_CLOSED;
        return CM_ERR_IO;
    }
    e = flush(ws);
    if (e != CM_OK)
        return e;
    return ws->closed ? CM_ERR_CLOSED : CM_OK;
}

void cm_ws_free(cm_ws *ws)
{
    if (ws == NULL)
        return;
    wslay_event_context_free(ws->ev);
    cm_io_close(&ws->io);
    free(ws->pre);
    free(ws);
}

cm_err cm_ws_flush(cm_ws *ws, int timeout_ms)
{
    for (;;) {
        cm_err e = flush(ws);
        int w;

        if (e != CM_OK)
            return e;
        if (!wslay_event_want_write(ws->ev))
            return CM_OK;
        w = cm_io_wait(&ws->io, 1, timeout_ms);
        if (w == 0)
            return CM_ERR_TIMEOUT;
        if (w < 0)
            return CM_ERR_IO;
    }
}

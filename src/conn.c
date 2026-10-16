/* See include/common.h for license and attribution. */
#include "conn.h"

#include <stdlib.h>
#include <string.h>

struct cm_conn {
    cm_ws *ws;
    cm_frame_parser fp;
    cm_noise_transport tr;
    int established;
    /* handshake scratch */
    uint8_t *server_hello;
    size_t server_hello_len;
    /* per-pump */
    cm_conn_frame_cb cb;
    void *user;
    uint8_t *scratch;
    size_t scratch_cap;
};

static cm_err grab_hello(void *u, const uint8_t *f, size_t n)
{
    cm_conn *c = (cm_conn *)u;

    if (c->server_hello != NULL)
        return CM_ERR_PROTO;
    c->server_hello = (uint8_t *)cm_memdup(f, n);
    if (c->server_hello == NULL)
        return CM_ERR_NOMEM;
    c->server_hello_len = n;
    return CM_OK;
}

static cm_err on_frame(void *u, const uint8_t *f, size_t n)
{
    cm_conn *c = (cm_conn *)u;
    cm_err e;

    if (n < CM_GCM_TAG_LEN)
        return CM_ERR_PROTO;
    if (n - CM_GCM_TAG_LEN > c->scratch_cap) {
        uint8_t *nb = (uint8_t *)realloc(c->scratch, n);

        if (nb == NULL)
            return CM_ERR_NOMEM;
        c->scratch = nb;
        c->scratch_cap = n;
    }
    e = cm_noise_transport_open(&c->tr, f, n, c->scratch);
    if (e != CM_OK)
        return e;
    return c->cb(c->user, c->scratch, n - CM_GCM_TAG_LEN);
}

static cm_err on_ws_msg(void *u, const uint8_t *d, size_t n)
{
    cm_conn *c = (cm_conn *)u;

    return cm_frame_parser_feed(&c->fp, d, n, c->established ? on_frame : grab_hello, c);
}

void cm_conn_free(cm_conn *c)
{
    if (c == NULL)
        return;
    cm_ws_free(c->ws);
    cm_frame_parser_free(&c->fp);
    cm_cleanse(&c->tr, sizeof(c->tr));
    free(c->server_hello);
    free(c->scratch);
    free(c);
}

void cm_conn_close(cm_conn *c)
{
    cm_ws_close(c->ws);
}

static cm_err send_frame(cm_conn *c, const uint8_t *hdr, size_t hl, const uint8_t *d, size_t n)
{
    cm_buf b;
    cm_err e;

    cm_buf_init(&b);
    e = cm_frame_encode(&b, hdr, hl, d, n);
    if (e == CM_OK && b.err != CM_OK)
        e = b.err;
    if (e == CM_OK)
        e = cm_ws_send(c->ws, b.data, b.len);
    cm_buf_free(&b);
    return e;
}

cm_err cm_conn_send(cm_conn *c, const uint8_t *data, size_t len)
{
    uint8_t *ct;
    cm_err e;

    if (!c->established)
        return CM_ERR_ARG;
    ct = (uint8_t *)malloc(len + CM_GCM_TAG_LEN);
    if (ct == NULL)
        return CM_ERR_NOMEM;
    e = cm_noise_transport_seal(&c->tr, data, len, ct);
    if (e == CM_OK)
        e = send_frame(c, NULL, 0, ct, len + CM_GCM_TAG_LEN);
    free(ct);
    return e;
}

cm_err cm_conn_pump(cm_conn *c, int timeout_ms, cm_conn_frame_cb cb, void *user)
{
    c->cb = cb;
    c->user = user;
    return cm_ws_pump(c->ws, timeout_ms, on_ws_msg, c);
}

static cm_err pump_until_hello(cm_conn *c, int timeout_ms)
{
    int tries = 0;

    while (c->server_hello == NULL) {
        cm_err e = cm_ws_pump(c->ws, timeout_ms, on_ws_msg, c);

        if (e == CM_ERR_TIMEOUT && ++tries >= 2)
            return CM_ERR_TIMEOUT;
        if (e != CM_OK && e != CM_ERR_TIMEOUT)
            return e;
    }
    return CM_OK;
}

cm_err cm_conn_open(cm_conn **out, cm_io *io, const cm_conn_params *p, cm_hs_error *err)
{
    cm_conn *c;
    cm_keypair eph;
    cm_handshake hs;
    uint8_t *hello = NULL, *finish = NULL, hdr[CM_CONN_HEADER_LEN];
    size_t hello_len = 0, finish_len = 0;
    cm_err e;
    int to = p->timeout_ms > 0 ? p->timeout_ms : 20000;

    *out = NULL;
    if (p->noise_key == NULL)
        return CM_ERR_ARG;
    c = (cm_conn *)calloc(1, sizeof(*c));
    if (c == NULL)
        return CM_ERR_NOMEM;
    cm_frame_parser_init(&c->fp);

    e = cm_ws_connect(&c->ws, io, p->host ? p->host : "web.whatsapp.com",
                      p->path ? p->path : "/ws/chat", p->origin ? p->origin : CM_WA_ORIGIN, to);
    if (e != CM_OK) {
        cm_frame_parser_free(&c->fp);
        free(c);
        return e;
    }
    /* from here on cm_conn_free also closes the io */
    e = cm_keypair_generate(&eph);
    if (e != CM_OK)
        goto fail;
    e = cm_handshake_begin(&hs, &eph, &hello, &hello_len);
    if (e != CM_OK)
        goto fail;
    cm_conn_header(hdr);
    e = send_frame(c, hdr, sizeof(hdr), hello, hello_len);
    if (e != CM_OK)
        goto fail;
    e = pump_until_hello(c, to);
    if (e != CM_OK)
        goto fail;
    e = cm_handshake_finish(&hs, c->server_hello, c->server_hello_len, p->noise_key,
                            p->client_payload, p->client_payload_len, p->now_unix, p->root_pub,
                            &finish, &finish_len, &c->tr, err);
    if (e != CM_OK)
        goto fail;
    e = send_frame(c, NULL, 0, finish, finish_len);
    if (e != CM_OK)
        goto fail;
    c->established = 1;
    e = cm_ws_flush(c->ws, to);
    if (e != CM_OK)
        goto fail;
    free(hello);
    free(finish);
    cm_cleanse(&hs, sizeof(hs));
    cm_cleanse(&eph, sizeof(eph));
    *out = c;
    return CM_OK;
fail:
    free(hello);
    free(finish);
    cm_cleanse(&eph, sizeof(eph));
    cm_conn_free(c);
    return e;
}

/* See include/common.h for license and attribution.
 * Port of whatsmeow client.go, request.go, keepalive.go, connectionevents.go, pair.go. */
#define _POSIX_C_SOURCE 200112L
#include "client_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "handshake.h"
#include "waAdv/WAAdv.pb-c.h"

#define KEEPALIVE_MIN_MS 20000
#define KEEPALIVE_MAX_MS 30000
#define KEEPALIVE_RESPONSE_MS 10000
#define DEFAULT_IQ_TIMEOUT_MS 75000

/* ---------------------------------------------------------------- helpers */
int64_t cmi_now_ms(void)
{
    struct timespec ts;

#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
    return (int64_t)time(NULL) * 1000;
}

void cmi_emit(cm_client *c, const cm_event *e)
{
    if (c->cb != NULL)
        c->cb(c->ud, e);
}

void cmi_save(cm_client *c)
{
    if (c->save_path != NULL)
        cm_device_save(c->dev, c->save_path);
}

cm_err cmi_node(cm_node *n, const char *tag)
{
    cm_node_init(n);
    return cm_node_set_tag(n, tag);
}

const char *cmi_attr(const cm_node *n, const char *key)
{
    const cm_value *v = cm_node_get_attr(n, key);

    return (v != NULL && v->type == CM_V_STR) ? v->u.str : NULL;
}

cm_err cmi_attr_jid(const cm_node *n, const char *key, cm_jid *out)
{
    const cm_value *v = cm_node_get_attr(n, key);

    if (v == NULL)
        return CM_ERR_INVALID_TYPE;
    if (v->type == CM_V_JID)
        return cm_jid_copy(out, &v->u.jid);
    if (v->type == CM_V_STR)
        return cm_jid_parse(out, v->u.str);
    return CM_ERR_INVALID_TYPE;
}

const uint8_t *cmi_bytes(const cm_node *n, size_t *len)
{
    if (n->content.type == CM_V_BYTES) {
        *len = n->content.u.bytes.len;
        return n->content.u.bytes.data;
    }
    if (n->content.type == CM_V_STR) {
        *len = strlen(n->content.u.str);
        return (const uint8_t *)n->content.u.str;
    }
    *len = 0;
    return NULL;
}

cm_err cmi_node_jid_attr(cm_node *n, const char *key, const cm_jid *j)
{
    return cm_node_set_attr_jid(n, key, j);
}

static cm_err server_jid(cm_jid *j)
{
    cm_jid_init(j);
    return cm_jid_set(j, "", CM_SERVER_DEFAULT_USER);
}

/* ---------------------------------------------------------------- lifecycle */
cm_client *cm_client_new(cm_device *dev, const cm_client_opts *opts)
{
    cm_client *c = (cm_client *)calloc(1, sizeof(*c));
    uint8_t r[4];
    char p[40];

    if (c == NULL)
        return NULL;
    c->dev = dev;
    if (opts != NULL)
        c->opts = *opts;
    c->host = cm_strdup(opts && opts->host ? opts->host : "web.whatsapp.com");
    c->port = cm_strdup(opts && opts->port ? opts->port : "443");
    c->ca_file = opts && opts->ca_file ? cm_strdup(opts->ca_file) : NULL;
    cm_random(r, 4);
    sprintf(p, "%u.%u-", (unsigned)(r[0] << 8 | r[1]), (unsigned)(r[2] << 8 | r[3]) % 100);
    c->id_prefix = cm_strdup(p);
    if (c->host == NULL || c->port == NULL || c->id_prefix == NULL) {
        cm_client_free(c);
        return NULL;
    }
    c->opts.host = c->opts.port = c->opts.ca_file = NULL;
    return c;
}

static void clear_waiters(cm_client *c, cm_err err)
{
    size_t i;

    for (i = 0; i < c->nwaiters; i++) {
        if (!c->waiters[i].done) {
            c->waiters[i].done = 1;
            c->waiters[i].err = err;
        }
    }
}

static void qr_clear(cm_client *c)
{
    size_t i;

    for (i = 0; i < c->nqr_pending; i++)
        free(c->qr_pending[i]);
    free(c->qr_pending);
    c->qr_pending = NULL;
    c->nqr_pending = c->qr_pos = 0;
}

static void qr_emit_next(cm_client *c)
{
    cm_event ev;

    memset(&ev, 0, sizeof(ev));
    if (c->qr_pos >= c->nqr_pending) {
        ev.type = CM_EVT_QR_TIMEOUT;
        qr_clear(c);
        cmi_emit(c, &ev);
        return;
    }
    ev.type = CM_EVT_QR;
    ev.qr = c->qr_pending[c->qr_pos];
    ev.qr_timeout_ms = c->qr_pos == 0 ? 60000 : 20000;
    c->next_qr_ms = cmi_now_ms() + ev.qr_timeout_ms;
    c->qr_pos++;
    cmi_emit(c, &ev);
}

void cm_client_free(cm_client *c)
{
    size_t i;

    if (c == NULL)
        return;
    qr_clear(c);
    cmi_messaging_free(c);
    cmi_media_free(c);
    cmi_appstate_free(c);
    cmi_user_free(c);
    cm_conn_free(c->conn);
    for (i = 0; i < c->nwaiters; i++) {
        free(c->waiters[i].id);
        if (c->waiters[i].resp) {
            cm_node_free(c->waiters[i].resp);
            free(c->waiters[i].resp);
        }
    }
    free(c->waiters);
    for (i = 0; i < c->qn; i++)
        cm_node_free(&c->queue[i]);
    free(c->queue);
    free(c->host);
    free(c->port);
    free(c->ca_file);
    free(c->save_path);
    free(c->id_prefix);
    free(c->keepalive_id);
    free(c);
}

void cm_client_set_event_cb(cm_client *c, cm_event_cb cb, void *user)
{
    c->cb = cb;
    c->ud = user;
}

void cm_client_set_ext_cb(cm_client *c, cm_ext_cb cb, void *user)
{
    c->ext_cb = cb;
    c->ext_ud = user;
}

void cmi_emit_ext(cm_client *c, int kind, const void *data)
{
    if (c->ext_cb != NULL)
        c->ext_cb(c->ext_ud, kind, data);
}

void cm_client_set_save_path(cm_client *c, const char *path)
{
    free(c->save_path);
    c->save_path = path ? cm_strdup(path) : NULL;
}

cm_device *cm_client_device(cm_client *c) { return c->dev; }
int cm_client_is_connected(const cm_client *c) { return c->conn != NULL; }
int cm_client_is_logged_in(const cm_client *c) { return c->logged_in; }

char *cm_client_new_id(cm_client *c)
{
    char buf[64];

    sprintf(buf, "%s%lu", c->id_prefix, (unsigned long)++c->id_counter);
    return cm_strdup(buf);
}

/* ---------------------------------------------------------------- connect */
static void schedule_keepalive(cm_client *c)
{
    uint8_t r[2];
    unsigned span = KEEPALIVE_MAX_MS - KEEPALIVE_MIN_MS;

    cm_random(r, 2);
    c->next_keepalive_ms = cmi_now_ms() + KEEPALIVE_MIN_MS + ((unsigned)(r[0] << 8 | r[1]) % span);
}

cm_err cm_client_connect(cm_client *c)
{
    cm_io io;
    cm_conn_params p;
    cm_hs_error herr;
    uint8_t *payload = NULL;
    size_t plen = 0;
    int to = c->opts.timeout_ms > 0 ? c->opts.timeout_ms : 20000;
    cm_err e;

    if (c->conn != NULL)
        return CM_ERR_ARG;
    e = cm_device_client_payload(c->dev, &payload, &plen);
    if (e != CM_OK)
        return e;
    if (c->opts.connect_io != NULL && c->opts.connect_io->ops != NULL) {
        io = *c->opts.connect_io;
        c->opts.connect_io->ops = NULL;
        e = CM_OK;
    } else if (c->opts.plain_tcp)
        e = cm_io_tcp_connect(&io, c->host, c->port, to);
    else
        e = cm_io_tls_connect(&io, c->host, c->port, c->ca_file, to);
    if (e != CM_OK) {
        free(payload);
        return e;
    }
    memset(&p, 0, sizeof(p));
    p.host = c->host;
    p.noise_key = &c->dev->noise_key;
    p.client_payload = payload;
    p.client_payload_len = plen;
    p.now_unix = (int64_t)time(NULL);
    p.root_pub = c->opts.root_pub;
    p.timeout_ms = to;
    memset(&herr, 0, sizeof(herr));
    e = cm_conn_open(&c->conn, &io, &p, &herr);
    free(payload);
    if (e != CM_OK) {
        cm_io_close(&io);
        return e;
    }
    c->logged_in = 0;
    c->expect_close = 0;
    c->keepalive_errors = 0;
    schedule_keepalive(c);
    return CM_OK;
}

static void drop_conn(cm_client *c, cm_err why, int emit)
{
    if (c->conn == NULL)
        return;
    cm_conn_free(c->conn);
    c->conn = NULL;
    c->logged_in = 0;
    clear_waiters(c, CM_ERR_CLOSED);
    free(c->keepalive_id);
    c->keepalive_id = NULL;
    if (emit) {
        cm_event ev;

        memset(&ev, 0, sizeof(ev));
        ev.type = CM_EVT_DISCONNECTED;
        ev.err = why;
        cmi_emit(c, &ev);
    }
}

void cm_client_disconnect(cm_client *c)
{
    c->expect_close = 1;
    drop_conn(c, CM_OK, 0);
}

/* ---------------------------------------------------------------- send */
cm_err cm_client_send_node(cm_client *c, const cm_node *n)
{
    uint8_t *data;
    size_t len;
    cm_err e;

    if (c->conn == NULL)
        return CM_ERR_CLOSED;
    e = cm_binary_marshal(n, &data, &len);
    if (e != CM_OK)
        return e;
    e = cm_conn_send(c->conn, data, len);
    free(data);
    return e;
}

/* ---------------------------------------------------------------- receive */
static int is_disconnect_tag(const char *tag)
{
    return strcmp(tag, "xmlstreamend") == 0 || strcmp(tag, "stream:error") == 0;
}

static cm_err enqueue(cm_client *c, cm_node *n)
{
    if (c->qn == c->qcap) {
        size_t nc = c->qcap ? c->qcap * 2 : 16;
        cm_node *nq = (cm_node *)realloc(c->queue, nc * sizeof(cm_node));

        if (nq == NULL)
            return CM_ERR_NOMEM;
        c->queue = nq;
        c->qcap = nc;
    }
    c->queue[c->qn++] = *n;
    cm_node_init(n);
    return CM_OK;
}

static int handled_tag(const char *t)
{
    return strcmp(t, "ack") != 0;
}

static cm_err on_frame(void *u, const uint8_t *frame, size_t len)
{
    cm_client *c = (cm_client *)u;
    uint8_t *plain = NULL;
    size_t plen = 0;
    cm_node n;
    const char *id;
    size_t i;

    if (cm_binary_unpack(frame, len, &plain, &plen) != CM_OK)
        return CM_OK; /* whatsmeow logs and ignores undecodable frames */
    cm_node_init(&n);
    if (cm_binary_unmarshal(plain, plen, &n) != CM_OK) {
        free(plain);
        cm_node_free(&n);
        return CM_OK;
    }
    free(plain);

    if (is_disconnect_tag(n.tag))
        clear_waiters(c, CM_ERR_CLOSED);
    id = cmi_attr(&n, "id");
    if (id != NULL && (strcmp(n.tag, "iq") == 0 || strcmp(n.tag, "ack") == 0)) {
        if (c->keepalive_id != NULL && strcmp(c->keepalive_id, id) == 0) {
            free(c->keepalive_id);
            c->keepalive_id = NULL;
            c->keepalive_errors = 0;
            c->last_keepalive_ok_ms = cmi_now_ms();
            cm_node_free(&n);
            return CM_OK;
        }
        for (i = 0; i < c->nwaiters; i++) {
            if (!c->waiters[i].done && strcmp(c->waiters[i].id, id) == 0) {
                cm_node *copy = (cm_node *)malloc(sizeof(cm_node));

                if (copy == NULL) {
                    cm_node_free(&n);
                    return CM_ERR_NOMEM;
                }
                *copy = n;
                c->waiters[i].resp = copy;
                c->waiters[i].done = 1;
                return CM_OK;
            }
        }
    }
    if (handled_tag(n.tag)) {
        cm_err e = enqueue(c, &n);

        if (e != CM_OK) {
            cm_node_free(&n);
            return e;
        }
    } else {
        cm_node_free(&n);
    }
    return CM_OK;
}

static cm_err pump_io(cm_client *c, int timeout_ms)
{
    cm_err e;

    if (c->conn == NULL)
        return CM_ERR_CLOSED;
    e = cm_conn_pump(c->conn, timeout_ms, on_frame, c);
    if (e == CM_OK || e == CM_ERR_TIMEOUT)
        return e;
    if (e == CM_ERR_NOMEM)
        return e;
    drop_conn(c, e, !c->expect_close);
    return CM_ERR_CLOSED;
}

/* ---------------------------------------------------------------- iq */
static struct cmi_waiter *add_waiter(cm_client *c, const char *id)
{
    struct cmi_waiter *w;

    if (c->nwaiters == c->capwaiters) {
        size_t nc = c->capwaiters ? c->capwaiters * 2 : 8;
        struct cmi_waiter *nw = (struct cmi_waiter *)realloc(c->waiters, nc * sizeof(*nw));

        if (nw == NULL)
            return NULL;
        c->waiters = nw;
        c->capwaiters = nc;
    }
    w = &c->waiters[c->nwaiters];
    memset(w, 0, sizeof(*w));
    w->id = cm_strdup(id);
    if (w->id == NULL)
        return NULL;
    c->nwaiters++;
    return w;
}

static cm_err iq_impl(cm_client *c, const char *xmlns, const char *type, const char *to,
                       cm_node *content, int timeout_ms, cm_node **resp, int multi)
{
    cm_node iq;
    char *id = cm_client_new_id(c);
    size_t widx;
    cm_err e;
    int64_t deadline;
    const char *rtype;
    cm_node *r;

    if (resp != NULL)
        *resp = NULL;
    if (id == NULL)
        return CM_ERR_NOMEM;
    if (add_waiter(c, id) == NULL) {
        free(id);
        return CM_ERR_NOMEM;
    }
    widx = c->nwaiters - 1;

    e = cmi_node(&iq, "iq");
    if (e == CM_OK) e = cm_node_set_attr_str(&iq, "id", id);
    if (e == CM_OK) e = cm_node_set_attr_str(&iq, "xmlns", xmlns);
    if (e == CM_OK) e = cm_node_set_attr_str(&iq, "type", type);
    if (e == CM_OK && to != NULL) {
        cm_jid j;

        cm_jid_init(&j);
        e = to[0] == '\0' ? server_jid(&j) : cm_jid_parse(&j, to);
        if (e == CM_OK)
            e = cm_node_set_attr_jid(&iq, "to", &j);
        cm_jid_free(&j);
    }
    if (e == CM_OK && content != NULL && multi) {
        size_t k;

        for (k = 0; e == CM_OK && k < cm_node_nchildren(content); k++)
            e = cm_node_add_child(&iq, &content->content.u.nodes.items[k]);
    } else if (e == CM_OK && content != NULL) {
        e = cm_node_add_child(&iq, content);
    }
    if (e == CM_OK)
        e = cm_client_send_node(c, &iq);
    cm_node_free(&iq);
    if (e != CM_OK)
        goto done;

    deadline = cmi_now_ms() + (timeout_ms > 0 ? timeout_ms : DEFAULT_IQ_TIMEOUT_MS);
    while (!c->waiters[widx].done) {
        int64_t left = deadline - cmi_now_ms();

        if (left <= 0) {
            e = CM_ERR_TIMEOUT;
            goto done;
        }
        e = pump_io(c, left > 200 ? 200 : (int)left);
        if (e != CM_OK && e != CM_ERR_TIMEOUT)
            goto done;
        e = CM_OK;
    }
    if (c->waiters[widx].err != CM_OK) {
        e = c->waiters[widx].err;
        goto done;
    }
    r = c->waiters[widx].resp;
    c->waiters[widx].resp = NULL;
    rtype = cmi_attr(r, "type");
    if (strcmp(r->tag, "iq") != 0 || rtype == NULL || (strcmp(rtype, "result") != 0 && strcmp(rtype, "error") != 0)) {
        e = CM_ERR_PROTO;
    } else if (strcmp(rtype, "error") == 0) {
        e = CM_ERR_PROTO;
    }
    if (resp != NULL && (e == CM_OK || strcmp(rtype ? rtype : "", "error") == 0)) {
        *resp = r;
    } else {
        cm_node_free(r);
        free(r);
    }
done:
    /* remove our waiter (it may not be last if nested calls happened; they always finish first) */
    free(c->waiters[widx].id);
    if (c->waiters[widx].resp) {
        cm_node_free(c->waiters[widx].resp);
        free(c->waiters[widx].resp);
    }
    c->nwaiters = widx;
    free(id);
    return e;
}

/* Sends n (which must carry attribute id) and waits for the server <ack>/<iq> with that id. */
cm_err cmi_send_wait(cm_client *c, const cm_node *n, const char *id, int timeout_ms, cm_node **resp)
{
    size_t widx;
    int64_t deadline;
    cm_err e;

    if (resp != NULL)
        *resp = NULL;
    if (add_waiter(c, id) == NULL)
        return CM_ERR_NOMEM;
    widx = c->nwaiters - 1;
    e = cm_client_send_node(c, n);
    deadline = cmi_now_ms() + (timeout_ms > 0 ? timeout_ms : DEFAULT_IQ_TIMEOUT_MS);
    while (e == CM_OK && !c->waiters[widx].done) {
        int64_t left = deadline - cmi_now_ms();

        if (left <= 0) {
            e = CM_ERR_TIMEOUT;
            break;
        }
        e = pump_io(c, left > 200 ? 200 : (int)left);
        if (e == CM_ERR_TIMEOUT)
            e = CM_OK;
    }
    if (e == CM_OK && c->waiters[widx].err != CM_OK)
        e = c->waiters[widx].err;
    if (e == CM_OK && resp != NULL) {
        *resp = c->waiters[widx].resp;
        c->waiters[widx].resp = NULL;
    }
    free(c->waiters[widx].id);
    if (c->waiters[widx].resp) {
        cm_node_free(c->waiters[widx].resp);
        free(c->waiters[widx].resp);
    }
    c->nwaiters = widx;
    return e;
}

cm_err cm_client_iq(cm_client *c, const char *xmlns, const char *type, const char *to,
                    cm_node *content, int timeout_ms, cm_node **resp)
{
    return iq_impl(c, xmlns, type, to, content, timeout_ms, resp, 0);
}

cm_err cm_client_iq_multi(cm_client *c, const char *xmlns, const char *type, const char *to,
                          cm_node *container, int timeout_ms, cm_node **resp)
{
    return iq_impl(c, xmlns, type, to, container, timeout_ms, resp, 1);
}

cm_err cm_client_set_passive(cm_client *c, int passive)
{
    cm_node ch;
    cm_node *resp = NULL;
    cm_err e = cmi_node(&ch, passive ? "passive" : "active");

    if (e != CM_OK)
        return e;
    e = cm_client_iq(c, "passive", "set", "", &ch, 0, &resp);
    cm_node_free(&ch);
    if (resp) {
        cm_node_free(resp);
        free(resp);
    }
    return e;
}

cm_err cm_client_send_presence(cm_client *c, int available)
{
    cm_node n;
    cm_err e = cmi_node(&n, "presence");

    if (e == CM_OK) e = cm_node_set_attr_str(&n, "type", available ? "available" : "unavailable");
    if (e == CM_OK && available && c->dev->push_name != NULL && c->dev->push_name[0])
        e = cm_node_set_attr_str(&n, "name", c->dev->push_name);
    if (e == CM_OK) e = cm_client_send_node(c, &n);
    cm_node_free(&n);
    return e;
}

/* ---------------------------------------------------------------- pairing */
static char *b64(const uint8_t *d, size_t n)
{
    char *o = (char *)malloc(4 * ((n + 2) / 3) + 1);

    if (o != NULL)
        EVP_EncodeBlock((unsigned char *)o, d, (int)n);
    return o;
}

cm_err cm_client_make_qr(const cm_client *c, const char *ref, char **out)
{
    char *noise = b64(c->dev->noise_key.pub, 32), *ident = b64(c->dev->identity_key.pub, 32);
    char *adv = b64(c->dev->adv_secret_key, 32), *s = NULL;

    if (noise && ident && adv) {
        size_t n = strlen(ref) + strlen(noise) + strlen(ident) + strlen(adv) + 96;

        s = (char *)malloc(n);
        if (s != NULL)
            sprintf(s, "https://wa.me/settings/linked_devices#%s,%s,%s,%s,9", ref, noise, ident, adv);
    }
    free(noise); free(ident); free(adv);
    *out = s;
    return s ? CM_OK : CM_ERR_NOMEM;
}

static void send_result(cm_client *c, const cm_node *req)
{
    cm_node r;
    cm_jid j;

    if (cmi_node(&r, "iq") != CM_OK)
        return;
    cm_jid_init(&j);
    if (cmi_attr_jid(req, "from", &j) == CM_OK)
        cm_node_set_attr_jid(&r, "to", &j);
    cm_jid_free(&j);
    if (cmi_attr(req, "id"))
        cm_node_set_attr_str(&r, "id", cmi_attr(req, "id"));
    cm_node_set_attr_str(&r, "type", "result");
    cm_client_send_node(c, &r);
    cm_node_free(&r);
}

static void handle_pair_device(cm_client *c, const cm_node *n, const cm_node *pd)
{
    size_t i;

    send_result(c, n);
    qr_clear(c);
    for (i = 0; i < cm_node_nchildren(pd); i++) {
        const cm_node *ref = cm_node_child_at(pd, i);
        size_t len;
        const uint8_t *d;
        char *refs, *qr = NULL, **nv;

        if (strcmp(ref->tag, "ref") != 0 || (d = cmi_bytes(ref, &len)) == NULL)
            continue;
        refs = cm_strndup((const char *)d, len);
        if (refs == NULL || cm_client_make_qr(c, refs, &qr) != CM_OK) {
            free(refs);
            continue;
        }
        free(refs);
        nv = (char **)realloc(c->qr_pending, (c->nqr_pending + 1) * sizeof(char *));
        if (nv == NULL) {
            free(qr);
            break;
        }
        c->qr_pending = nv;
        c->qr_pending[c->nqr_pending++] = qr;
    }
    qr_emit_next(c);
}

static void send_pair_error(cm_client *c, const char *req_id, int code, const char *text)
{
    cm_node iq, err;
    cm_jid j;
    char codebuf[16];

    if (cmi_node(&iq, "iq") != CM_OK)
        return;
    cm_jid_init(&j);
    server_jid(&j);
    cm_node_set_attr_jid(&iq, "to", &j);
    cm_jid_free(&j);
    cm_node_set_attr_str(&iq, "type", "error");
    cm_node_set_attr_str(&iq, "id", req_id);
    cmi_node(&err, "error");
    sprintf(codebuf, "%d", code);
    cm_node_set_attr_str(&err, "code", codebuf);
    cm_node_set_attr_str(&err, "text", text);
    cm_node_add_child(&iq, &err);
    cm_client_send_node(c, &iq);
    cm_node_free(&iq);
}

/* concat helper */
static uint8_t *cat3(const uint8_t *a, size_t al, const uint8_t *b, size_t bl, const uint8_t *d,
                     size_t dl, const uint8_t *e, size_t el, size_t *out)
{
    uint8_t *r = (uint8_t *)malloc(al + bl + dl + el + 1);

    if (r == NULL)
        return NULL;
    memcpy(r, a, al);
    memcpy(r + al, b, bl);
    memcpy(r + al + bl, d, dl);
    if (el)
        memcpy(r + al + bl + dl, e, el);
    *out = al + bl + dl + el;
    return r;
}

static cm_err do_pair(cm_client *c, const uint8_t *ident, size_t ilen, const char *req_id,
                      const char *biz, const char *platform, const cm_jid *jid, const cm_jid *lid)
{
    WAAdv__ADVSignedDeviceIdentityHMAC *hm = waadv__advsigned_device_identity_hmac__unpack(NULL, ilen, ident);
    WAAdv__ADVSignedDeviceIdentity *di = NULL;
    WAAdv__ADVDeviceIdentity *dd = NULL;
    uint8_t mac[32], *msg = NULL, sig[64], *selfsigned = NULL;
    uint8_t prefix[2] = {6, 0};
    size_t mlen, ss_len = 0;
    cm_err e = CM_ERR_PROTO;
    cm_node iq, pds, dev;
    cm_jid sj, main_lid;
    char *akey = NULL;
    uint8_t main_ident[32];
    uint8_t *packed_full = NULL;

    if (hm == NULL) {
        send_pair_error(c, req_id, 500, "internal-error");
        return CM_ERR_PROTO;
    }
    {
        int hosted = hm->accounttype == WAADV__ADVENCRYPTION_TYPE__HOSTED;
        uint8_t hp[2] = {6, 5};

        msg = cat3(hosted ? hp : (const uint8_t *)"", hosted ? 2 : 0, hm->details.data, hm->details.len,
                   (const uint8_t *)"", 0, NULL, 0, &mlen);
        if (msg == NULL || cm_hmac_sha256(c->dev->adv_secret_key, 32, msg, mlen, mac) != CM_OK ||
            hm->hmac.len != 32 || cm_ct_equal(mac, hm->hmac.data, 32) == 0) {
            send_pair_error(c, req_id, 401, "hmac-mismatch");
            e = CM_ERR_AUTH;
            goto out;
        }
    }
    free(msg);
    msg = NULL;
    di = waadv__advsigned_device_identity__unpack(NULL, hm->details.len, hm->details.data);
    if (di == NULL || !di->has_details) {
        send_pair_error(c, req_id, 500, "internal-error");
        goto out;
    }
    dd = waadv__advdevice_identity__unpack(NULL, di->details.len, di->details.data);
    if (dd == NULL) {
        send_pair_error(c, req_id, 500, "internal-error");
        goto out;
    }
    /* verifyAccountSignature */
    if (di->accountsignaturekey.len != 32 || di->accountsignature.len != 64) {
        send_pair_error(c, req_id, 401, "signature-mismatch");
        e = CM_ERR_AUTH;
        goto out;
    }
    {
        int hosted = dd->devicetype == WAADV__ADVENCRYPTION_TYPE__HOSTED;

        prefix[1] = hosted ? 5 : 0;
        msg = cat3(prefix, 2, di->details.data, di->details.len, c->dev->identity_key.pub, 32, NULL, 0, &mlen);
        if (msg == NULL || cm_xeddsa_verify(di->accountsignaturekey.data, msg, mlen, di->accountsignature.data) != CM_OK) {
            send_pair_error(c, req_id, 401, "signature-mismatch");
            e = CM_ERR_AUTH;
            goto out;
        }
    }
    free(msg);
    /* generateDeviceSignature */
    prefix[0] = 6; prefix[1] = 1;
    msg = cat3(prefix, 2, di->details.data, di->details.len, c->dev->identity_key.pub, 32,
               di->accountsignaturekey.data, 32, &mlen);
    if (msg == NULL || cm_xeddsa_sign(c->dev->identity_key.priv, msg, mlen, sig) != CM_OK) {
        e = CM_ERR_CRYPTO;
        goto out;
    }
    di->has_devicesignature = 1;
    di->devicesignature.data = sig;
    di->devicesignature.len = 64;
    memcpy(main_ident, di->accountsignaturekey.data, 32);

    /* self-signed identity: same message without AccountSignatureKey */
    di->has_accountsignaturekey = 0;
    di->accountsignaturekey.len = 0;
    di->accountsignaturekey.data = NULL;
    ss_len = waadv__advsigned_device_identity__get_packed_size(di);
    selfsigned = (uint8_t *)malloc(ss_len ? ss_len : 1);
    if (selfsigned == NULL) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    waadv__advsigned_device_identity__pack(di, selfsigned);
    (void)packed_full;

    /* persist */
    e = cm_device_set_id(c->dev, jid);
    if (e != CM_OK)
        goto out;
    cm_jid_free(&c->dev->lid);
    cm_jid_init(&c->dev->lid);
    if (lid != NULL && !cm_jid_is_empty(lid))
        cm_jid_copy(&c->dev->lid, lid);
    free(c->dev->account);
    c->dev->account = (uint8_t *)cm_memdup(selfsigned, ss_len);
    c->dev->account_len = ss_len;
    free(c->dev->business_name);
    c->dev->business_name = cm_strdup(biz ? biz : "");
    free(c->dev->platform);
    c->dev->platform = cm_strdup(platform ? platform : "");
    /* main device identity: stored under the main device LID (device 0) address */
    cm_jid_init(&main_lid);
    if (lid != NULL && !cm_jid_is_empty(lid) && cm_jid_copy(&main_lid, lid) == CM_OK) {
        main_lid.device = 0;
        if (cm_signal_address_string(&main_lid, &akey) == CM_OK) {
            cm_kvmap_put(&c->dev->identities, akey, main_ident, 32);
            free(akey);
        }
    }
    cm_jid_free(&main_lid);
    cmi_save(c);
    c->expect_close = 1;

    /* <iq to=server type=result id><pair-device-sign><device-identity key-index>bytes */
    cmi_node(&iq, "iq");
    cm_jid_init(&sj);
    server_jid(&sj);
    cm_node_set_attr_jid(&iq, "to", &sj);
    cm_jid_free(&sj);
    cm_node_set_attr_str(&iq, "type", "result");
    cm_node_set_attr_str(&iq, "id", req_id);
    cmi_node(&pds, "pair-device-sign");
    cmi_node(&dev, "device-identity");
    cm_node_set_attr_u64(&dev, "key-index", dd->has_keyindex ? dd->keyindex : 0);
    cm_node_set_content_bytes(&dev, selfsigned, ss_len);
    cm_node_add_child(&pds, &dev);
    cm_node_add_child(&iq, &pds);
    e = cm_client_send_node(c, &iq);
    cm_node_free(&iq);
out:
    free(msg);
    free(selfsigned);
    if (di) {
        di->has_devicesignature = 0;
        di->devicesignature.data = NULL;
        waadv__advsigned_device_identity__free_unpacked(di, NULL);
    }
    if (dd) waadv__advdevice_identity__free_unpacked(dd, NULL);
    waadv__advsigned_device_identity_hmac__free_unpacked(hm, NULL);
    return e;
}

static void handle_pair_success(cm_client *c, const cm_node *n, const cm_node *ps)
{
    const cm_node *di = cm_node_child(ps, "device-identity");
    const cm_node *biz = cm_node_child(ps, "biz");
    const cm_node *dev = cm_node_child(ps, "device");
    const cm_node *plat = cm_node_child(ps, "platform");
    const char *id = cmi_attr(n, "id");
    size_t ilen = 0;
    const uint8_t *ident = di ? cmi_bytes(di, &ilen) : NULL;
    cm_jid jid, lid;
    cm_err e;
    cm_event ev;

    qr_clear(c);

    cm_jid_init(&jid);
    cm_jid_init(&lid);
    if (id == NULL || ident == NULL || dev == NULL || cmi_attr_jid(dev, "jid", &jid) != CM_OK) {
        memset(&ev, 0, sizeof(ev));
        ev.type = CM_EVT_PAIR_ERROR;
        ev.err = CM_ERR_PROTO;
        cmi_emit(c, &ev);
        goto out;
    }
    cmi_attr_jid(dev, "lid", &lid);
    e = do_pair(c, ident, ilen, id, biz ? cmi_attr(biz, "name") : NULL, plat ? cmi_attr(plat, "name") : NULL,
                &jid, &lid);
    memset(&ev, 0, sizeof(ev));
    if (e != CM_OK) {
        ev.type = CM_EVT_PAIR_ERROR;
        ev.err = e;
    } else {
        ev.type = CM_EVT_PAIR_SUCCESS;
        ev.jid = &jid;
        ev.lid = &lid;
        ev.platform = c->dev->platform;
        ev.business_name = c->dev->business_name;
    }
    cmi_emit(c, &ev);
out:
    cm_jid_free(&jid);
    cm_jid_free(&lid);
}

/* ---------------------------------------------------------------- handlers */
static void handle_iq(cm_client *c, const cm_node *n)
{
    const char *type = cmi_attr(n, "type");
    const char *xmlns = cmi_attr(n, "xmlns");
    const cm_node *ch;

    if (cm_node_nchildren(n) == 1) {
        ch = cm_node_child_at(n, 0);
        if (strcmp(ch->tag, "pair-device") == 0) {
            c->logged_in = 0;
            handle_pair_device(c, n, ch);
            return;
        }
        if (strcmp(ch->tag, "pair-success") == 0) {
            handle_pair_success(c, n, ch);
            return;
        }
    }
    if (type != NULL && strcmp(type, "get") == 0 && xmlns != NULL && strcmp(xmlns, "urn:xmpp:ping") == 0)
        send_result(c, n);
}

static void handle_success(cm_client *c, const cm_node *n)
{
    cm_event ev;
    cm_jid lid;
    const char *t = cmi_attr(n, "t");

    if (!c->dev->has_id)
        return; /* success without pairing: ignore, like whatsmeow */
    c->logged_in = 1;
    if (t != NULL)
        c->server_offset = (int64_t)strtoll(t, NULL, 10) - (int64_t)time(NULL);
    cm_jid_init(&lid);
    if (cmi_attr_jid(n, "lid", &lid) == CM_OK && !cm_jid_is_empty(&lid) && cm_jid_is_empty(&c->dev->lid)) {
        cm_jid_free(&c->dev->lid);
        cm_jid_init(&c->dev->lid);
        cm_jid_copy(&c->dev->lid, &lid);
        cmi_save(c);
    }
    cm_jid_free(&lid);
    cmi_upload_prekeys_if_needed(c);
    cm_client_set_passive(c, 0);
    memset(&ev, 0, sizeof(ev));
    ev.type = CM_EVT_CONNECTED;
    cmi_emit(c, &ev);
    cmi_messaging_on_connected(c);
    cmi_appstate_on_connected(c);
    cmi_user_on_connected(c);
}

static void handle_failure(cm_client *c, const cm_node *n)
{
    const char *r = cmi_attr(n, "reason");
    int reason = r ? atoi(r) : 0;
    cm_event ev;

    memset(&ev, 0, sizeof(ev));
    c->logged_in = 0;
    if (reason == 401 || reason == 403 || reason == 405 || reason == 406 || reason == 500 || reason == 503) {
        /* 503 and 500 are retryable in whatsmeow; everything else is final */
    }
    if (reason == 401 || reason == 403 || reason == 406) {
        ev.type = CM_EVT_LOGGED_OUT;
        ev.reason = r;
        c->expect_close = 1;
        cmi_emit(c, &ev);
        return;
    }
    ev.type = CM_EVT_STREAM_ERROR;
    ev.reason = r ? r : "failure";
    if (reason != 503 && reason != 500)
        c->expect_close = 1;
    cmi_emit(c, &ev);
}

static void handle_stream_error(cm_client *c, const cm_node *n)
{
    const char *code = cmi_attr(n, "code");
    const cm_node *conflict = cm_node_child(n, "conflict");
    const char *ctype = conflict ? cmi_attr(conflict, "type") : NULL;
    cm_event ev;

    c->logged_in = 0;
    memset(&ev, 0, sizeof(ev));
    if (code != NULL && strcmp(code, "515") == 0) {
        c->reconnect = 1; /* normal after pairing */
        return;
    }
    if (code != NULL && strcmp(code, "401") == 0 && ctype != NULL && strcmp(ctype, "device_removed") == 0) {
        c->expect_close = 1;
        ev.type = CM_EVT_LOGGED_OUT;
        ev.reason = "device_removed";
    } else {
        if (ctype != NULL && strcmp(ctype, "replaced") == 0)
            c->expect_close = 1;
        ev.type = CM_EVT_STREAM_ERROR;
        ev.reason = ctype ? ctype : (code ? code : "stream:error");
    }
    cmi_emit(c, &ev);
}

static void dispatch(cm_client *c, const cm_node *n)
{
    const char *t = n->tag;

    if (strcmp(t, "success") == 0)
        handle_success(c, n);
    else if (strcmp(t, "failure") == 0)
        handle_failure(c, n);
    else if (strcmp(t, "stream:error") == 0)
        handle_stream_error(c, n);
    else if (strcmp(t, "xmlstreamend") == 0) {
        if (!c->expect_close && !c->reconnect)
            drop_conn(c, CM_ERR_CLOSED, 1);
    } else if (strcmp(t, "iq") == 0)
        handle_iq(c, n);
    else if (strcmp(t, "message") == 0)
        cmi_handle_message(c, n);
    else if (strcmp(t, "receipt") == 0)
        cmi_messaging_handle_receipt(c, n);
    else
        cmi_ext_dispatch(c, n);
}

/* ---------------------------------------------------------------- keepalive */
static void run_keepalive(cm_client *c)
{
    int64_t now = cmi_now_ms();
    cm_node ch, iq;
    char *id;
    cm_jid j;
    cm_event ev;

    if (c->conn == NULL)
        return;
    if (c->keepalive_id != NULL && now >= c->keepalive_deadline_ms) {
        free(c->keepalive_id);
        c->keepalive_id = NULL;
        c->keepalive_errors++;
        memset(&ev, 0, sizeof(ev));
        ev.type = CM_EVT_KEEPALIVE_TIMEOUT;
        cmi_emit(c, &ev);
        if (now - c->last_keepalive_ok_ms > 180000 && c->last_keepalive_ok_ms != 0) {
            drop_conn(c, CM_ERR_TIMEOUT, 1); /* caller may reconnect */
            return;
        }
    }
    if (now < c->next_keepalive_ms || c->keepalive_id != NULL)
        return;
    schedule_keepalive(c);
    if (c->last_keepalive_ok_ms == 0)
        c->last_keepalive_ok_ms = now;
    id = cm_client_new_id(c);
    if (id == NULL)
        return;
    cmi_node(&iq, "iq");
    cm_node_set_attr_str(&iq, "id", id);
    cm_node_set_attr_str(&iq, "xmlns", "w:p");
    cm_node_set_attr_str(&iq, "type", "get");
    cm_jid_init(&j);
    server_jid(&j);
    cm_node_set_attr_jid(&iq, "to", &j);
    cm_jid_free(&j);
    (void)ch;
    if (cm_client_send_node(c, &iq) == CM_OK) {
        c->keepalive_id = id;
        c->keepalive_deadline_ms = now + KEEPALIVE_RESPONSE_MS;
    } else {
        free(id);
    }
    cm_node_free(&iq);
}

/* ---------------------------------------------------------------- main loop */
cm_err cm_client_run_once(cm_client *c, int timeout_ms)
{
    cm_err e;

    if (c->conn == NULL && !c->reconnect)
        return CM_ERR_CLOSED;
    if (c->conn != NULL) {
        e = pump_io(c, timeout_ms);
        if (e == CM_ERR_NOMEM)
            return e;
    }
    while (c->qn > 0) {
        cm_node n = c->queue[0];

        memmove(&c->queue[0], &c->queue[1], (c->qn - 1) * sizeof(cm_node));
        c->qn--;
        dispatch(c, &n);
        cm_node_free(&n);
    }
    if (c->reconnect) {
        c->reconnect = 0;
        c->expect_close = 1;
        drop_conn(c, CM_OK, 0);
        c->expect_close = 0;
        e = cm_client_connect(c);
        if (e != CM_OK) {
            cm_event ev;

            memset(&ev, 0, sizeof(ev));
            ev.type = CM_EVT_DISCONNECTED;
            ev.err = e;
            cmi_emit(c, &ev);
            return CM_ERR_CLOSED;
        }
    }
    if (c->nqr_pending > 0 && cmi_now_ms() >= c->next_qr_ms)
        qr_emit_next(c);
    run_keepalive(c);
    return c->conn != NULL ? CM_OK : CM_ERR_CLOSED;
}

cm_err cm_client_run(cm_client *c)
{
    cm_err e;

    do {
        e = cm_client_run_once(c, 500);
    } while (e == CM_OK);
    return e;
}

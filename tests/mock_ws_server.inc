/* Forked mock WhatsApp websocket+Noise server; needs mock_server.inc and wslay first. */
struct srv {
    int fd;
    struct server sv;
    struct opts opts;
    wslay_event_context_ptr ev;
    int state;
    cm_noise_transport tr;
    cm_frame_parser fp;
    int dead;
    int any_payload;
    void (*app)(struct srv *, const uint8_t *, size_t);
    void (*ready)(struct srv *);
};

static ssize_t srv_recv(wslay_event_context_ptr ev, uint8_t *b, size_t n, int f, void *u)
{
    struct srv *s = (struct srv *)u;
    ssize_t r = recv(s->fd, b, n, MSG_DONTWAIT);

    (void)f;
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        wslay_event_set_error(ev, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }
    if (r <= 0) {
        s->dead = 1;
        wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }
    return r;
}

static ssize_t srv_send(wslay_event_context_ptr ev, const uint8_t *b, size_t n, int f, void *u)
{
    struct srv *s = (struct srv *)u;
    ssize_t r = send(s->fd, b, n, 0);

    (void)f;
    if (r <= 0) {
        s->dead = 1;
        wslay_event_set_error(ev, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }
    return r;
}

static void srv_queue(struct srv *s, const uint8_t *hdr, size_t hl, const uint8_t *d, size_t n)
{
    cm_buf b;
    struct wslay_event_msg m;

    cm_buf_init(&b);
    cm_frame_encode(&b, hdr, hl, d, n);
    m.opcode = WSLAY_BINARY_FRAME;
    m.msg = b.data;
    m.msg_length = b.len;
    wslay_event_queue_msg(s->ev, &m);
    cm_buf_free(&b);
}

static void srv_send_plain(struct srv *s, const uint8_t *d, size_t n)
{
    uint8_t *ct = (uint8_t *)malloc(n + 16);

    cm_noise_transport_seal(&s->tr, d, n, ct);
    srv_queue(s, NULL, 0, ct, n + 16);
    free(ct);
}

static cm_err srv_frame(void *u, const uint8_t *f, size_t n)
{
    struct srv *s = (struct srv *)u;

    if (s->state == 0) {
        size_t hl;
        uint8_t *sh = server_hello(&s->sv, &s->opts, f, n, &hl, NULL);

        if (sh == NULL)
            return CM_ERR_PROTO;
        srv_queue(s, NULL, 0, sh, hl);
        free(sh);
        s->state = 1;
    } else if (s->state == 1) {
        WAWebProtobufsWa6__HandshakeMessage *fin =
            waweb_protobufs_wa6__handshake_message__unpack(NULL, n, f);
        uint8_t cs[32], *plain;

        if (fin == NULL || fin->clientfinish == NULL)
            return CM_ERR_PROTO;
        if (cm_noise_decrypt(&s->sv.nh, fin->clientfinish->static_.data, 48, cs) != CM_OK)
            return CM_ERR_AUTH;
        cm_noise_mix_shared_secret(&s->sv.nh, s->sv.eph.priv, cs);
        plain = (uint8_t *)malloc(fin->clientfinish->payload.len);
        if (cm_noise_decrypt(&s->sv.nh, fin->clientfinish->payload.data,
                             fin->clientfinish->payload.len, plain) != CM_OK ||
            fin->clientfinish->payload.len < 16 || (!s->any_payload && memcmp(plain, "payload", 7) != 0))
            return CM_ERR_AUTH;
        free(plain);
        waweb_protobufs_wa6__handshake_message__free_unpacked(fin, NULL);
        cm_noise_finish(&s->sv.nh, &s->tr);
        {   /* the responder uses the keys the other way round */
            uint8_t t[32];

            memcpy(t, s->tr.write_key, 32);
            memcpy(s->tr.write_key, s->tr.read_key, 32);
            memcpy(s->tr.read_key, t, 32);
        }
        s->state = 2;
        if (s->ready)
            s->ready(s);
    } else {
        uint8_t *pt;
        size_t pl;

        if (n < 16)
            return CM_ERR_PROTO;
        pl = n - 16;
        pt = (uint8_t *)malloc(pl + 1);
        if (cm_noise_transport_open(&s->tr, f, n, pt) != CM_OK)
            return CM_ERR_AUTH;
        s->app(s, pt, pl);
        free(pt);
    }
    return CM_OK;
}

static void srv_msg(wslay_event_context_ptr ev, const struct wslay_event_on_msg_recv_arg *a,
                    void *u)
{
    struct srv *s = (struct srv *)u;
    const uint8_t *d = a->msg;
    size_t n = a->msg_length;

    (void)ev;
    if (a->opcode != WSLAY_BINARY_FRAME)
        return;
    if (s->state == 0) { /* first message carries the 4-byte connection header */
        uint8_t want[4];

        cm_conn_header(want);
        if (n < 4 || memcmp(d, want, 4) != 0) {
            s->dead = 1;
            return;
        }
        d += 4;
        n -= 4;
    }
    if (cm_frame_parser_feed(&s->fp, d, n, srv_frame, s) != CM_OK)
        s->dead = 1;
}

static int srv_genmask(wslay_event_context_ptr ev, uint8_t *b, size_t n, void *u)
{
    (void)ev; (void)b; (void)n; (void)u;
    return 0; /* servers do not mask */
}

static int server_main(int fd, struct server *sv, void (*app)(struct srv *, const uint8_t *, size_t),
                       void (*ready)(struct srv *))
{
    struct srv s;
    char req[4096], *k, resp[512], acc[29], key[64];
    size_t got = 0, i;
    struct wslay_event_callbacks cb;

    memset(&s, 0, sizeof(s));
    s.fd = fd;
    s.sv = *sv;
    s.any_payload = app != NULL && app != (void *)0 && ready != NULL;
    s.app = app;
    s.ready = ready;
    cm_frame_parser_init(&s.fp);
    while (got < sizeof(req) - 1) {
        ssize_t r = recv(fd, req + got, 1, 0);

        if (r <= 0)
            return 1;
        got += (size_t)r;
        req[got] = '\0';
        if (got >= 4 && strcmp(req + got - 4, "\r\n\r\n") == 0)
            break;
    }
    k = strstr(req, "Sec-WebSocket-Key: ");
    if (k == NULL || strstr(req, "Origin: https://web.whatsapp.com\r\n") == NULL ||
        strncmp(req, "GET /ws/chat HTTP/1.1\r\n", 23) != 0)
        return 2;
    k += 19;
    for (i = 0; k[i] && k[i] != '\r' && i < sizeof(key) - 1; i++)
        key[i] = k[i];
    key[i] = '\0';
    cm_ws_accept_key(key, acc);
    /* send the 101 together with nothing else, split in two writes to exercise the parser */
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n", acc);
    send(fd, resp, strlen(resp), 0);

    memset(&cb, 0, sizeof(cb));
    cb.recv_callback = srv_recv;
    cb.send_callback = srv_send;
    cb.genmask_callback = srv_genmask;
    cb.on_msg_recv_callback = srv_msg;
    wslay_event_context_server_init(&s.ev, &cb, &s);
    while (!s.dead && (wslay_event_want_read(s.ev) || wslay_event_want_write(s.ev))) {
        if (wslay_event_send(s.ev) != 0)
            break;
        if (!wslay_event_want_write(s.ev)) {
            struct pollfd pf;

            pf.fd = fd;
            pf.events = POLLIN;
            poll(&pf, 1, 5000);
        }
        if (wslay_event_want_read(s.ev) && wslay_event_recv(s.ev) != 0)
            break;
    }
    wslay_event_send(s.ev);
    wslay_event_context_free(s.ev);
    cm_frame_parser_free(&s.fp);
    return s.dead && s.state != 2 ? 3 : 0;
}


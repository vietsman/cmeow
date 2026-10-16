/*
 * Loopback test of the whole transport stack: cm_conn (websocket upgrade via
 * wslay, frame layer, Noise XX handshake, encrypted transport) against a mock
 * server running in a forked child on a socketpair. Optionally (argv[1] =
 * "tls") the TCP path is not covered here; TLS needs a certificate.
 */
#define _POSIX_C_SOURCE 200112L
#include "conn.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <wslay/wslay.h>

#include "waCert/WACert.pb-c.h"
#include "waWa6/WAWebProtobufsWa6.pb-c.h"

static int g_failed, g_checks;

#define CHECK_TRUE(cond)                                                       \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(cond)) {                                                         \
            g_failed++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                      \
    } while (0)

#include "mock_server.inc"

#include "mock_ws_server.inc"

static void echo_app(struct srv *s, const uint8_t *pt, size_t pl)
{
    uint8_t *r = (uint8_t *)malloc(pl + 5);

    memcpy(r, "echo:", 5);
    memcpy(r + 5, pt, pl);
    srv_send_plain(s, r, pl + 5);
    if (pl == 3 && memcmp(pt, "bye", 3) == 0)
        wslay_event_queue_close(s->ev, WSLAY_CODE_NORMAL_CLOSURE, NULL, 0);
    free(r);
}

/* ---------------- client side ---------------- */
struct got {
    uint8_t *data[8];
    size_t len[8];
    int n;
};

static cm_err collect(void *u, const uint8_t *f, size_t n)
{
    struct got *g = (struct got *)u;

    if (g->n >= 8)
        return CM_ERR_PROTO;
    g->data[g->n] = (uint8_t *)cm_memdup(f, n);
    g->len[g->n++] = n;
    return CM_OK;
}

static int wait_frame(cm_conn *c, struct got *g, cm_err *last)
{
    int i;

    for (i = 0; i < 200 && g->n == 0; i++) {
        *last = cm_conn_pump(c, 100, collect, g);
        if (*last != CM_OK && *last != CM_ERR_TIMEOUT)
            return 0;
    }
    return g->n > 0;
}

static void drop(struct got *g)
{
    int i;

    for (i = 0; i < g->n; i++)
        free(g->data[i]);
    g->n = 0;
}

static pid_t spawn_server(struct server *sv, int *cfd)
{
    int sp[2];
    pid_t pid;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
        return -1;
    pid = fork();
    if (pid == 0) {
        int rc;

        close(sp[0]);
        rc = server_main(sp[1], sv, echo_app, NULL);
        close(sp[1]);
        _exit(rc);
    }
    close(sp[1]);
    *cfd = sp[0];
    return pid;
}

int main(void)
{
    struct server sv;
    cm_keypair nk;
    cm_conn_params p;
    cm_conn *c = NULL;
    cm_io io;
    cm_hs_error herr;
    int fd, status;
    pid_t pid;
    cm_err e, last = CM_OK;
    struct got g;
    uint8_t *big;
    size_t i;

    make_server(&sv);
    cm_keypair_generate(&nk);
    memset(&p, 0, sizeof(p));
    p.noise_key = &nk;
    p.client_payload = (const uint8_t *)"payload";
    p.client_payload_len = 7;
    p.now_unix = NOW;
    p.root_pub = sv.root.pub;
    p.timeout_ms = 5000;
    memset(&g, 0, sizeof(g));

    /* ---- happy path ---- */
    pid = spawn_server(&sv, &fd);
    CHECK_TRUE(pid > 0);
    io = cm_io_from_fd(fd);
    memset(&herr, 0, sizeof(herr));
    e = cm_conn_open(&c, &io, &p, &herr);
    CHECK_TRUE(e == CM_OK);
    if (e != CM_OK)
        fprintf(stderr, "open: %s %s\n", cm_strerror(e), herr.message);
    if (c != NULL) {
        e = cm_conn_send(c, (const uint8_t *)"hello", 5); CHECK_TRUE(e == CM_OK);
        CHECK_TRUE(wait_frame(c, &g, &last));
        CHECK_TRUE(g.n == 1 && g.len[0] == 10 && memcmp(g.data[0], "echo:hello", 10) == 0);
        drop(&g);

        /* large message: spans many socket reads and several wslay chunks */
        big = (uint8_t *)malloc(300000);
        for (i = 0; i < 300000; i++)
            big[i] = (uint8_t)(i * 31 + 7);
        CHECK_TRUE(cm_conn_send(c, big, 300000) == CM_OK);
        CHECK_TRUE(cm_conn_send(c, (const uint8_t *)"two", 3) == CM_OK);
        for (i = 0; i < 200 && g.n < 2; i++) {
            last = cm_conn_pump(c, 100, collect, &g);
            if (last != CM_OK && last != CM_ERR_TIMEOUT)
                break;
        }
        CHECK_TRUE(g.n == 2 && g.len[0] == 300005 && g.len[1] == 8);
        if (g.n == 2 && g.len[0] == 300005 && g.len[1] == 8) {
            CHECK_TRUE(memcmp(g.data[0], "echo:", 5) == 0);
            CHECK_TRUE(memcmp(g.data[0] + 5, big, 300000) == 0);
            CHECK_TRUE(memcmp(g.data[1], "echo:two", 8) == 0);
        }
        drop(&g);
        free(big);

        /* server closes after "bye": we must see CM_ERR_CLOSED */
        CHECK_TRUE(cm_conn_send(c, (const uint8_t *)"bye", 3) == CM_OK);
        last = CM_OK;
        for (i = 0; i < 200 && last != CM_ERR_CLOSED; i++) {
            last = cm_conn_pump(c, 100, collect, &g);
            if (last != CM_OK && last != CM_ERR_TIMEOUT && last != CM_ERR_CLOSED)
                break;
        }
        CHECK_TRUE(last == CM_ERR_CLOSED);
        drop(&g);
        cm_conn_free(c);
    }
    waitpid(pid, &status, 0);
    CHECK_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* ---- wrong certificate root: handshake must fail ---- */
    pid = spawn_server(&sv, &fd);
    io = cm_io_from_fd(fd);
    {
        cm_keypair other;

        cm_keypair_generate(&other);
        p.root_pub = other.pub;
    }
    memset(&herr, 0, sizeof(herr));
    c = NULL;
    e = cm_conn_open(&c, &io, &p, &herr);
    CHECK_TRUE(e != CM_OK && c == NULL);
    CHECK_TRUE(herr.message[0] != '\0');
    waitpid(pid, &status, 0);

    /* ---- peer that is not a websocket server ---- */
    {
        int sp[2];

        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        send(sp[1], "HTTP/1.1 200 OK\r\n\r\n", 19, 0);
        io = cm_io_from_fd(sp[0]);
        p.root_pub = sv.root.pub;
        p.timeout_ms = 500;
        e = cm_conn_open(&c, &io, &p, NULL);
        CHECK_TRUE(e == CM_ERR_PROTO);
        cm_io_close(&io);
        close(sp[1]);
    }

    /* ---- peer that never answers: timeout, not a hang ---- */
    {
        int sp[2];

        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        io = cm_io_from_fd(sp[0]);
        p.timeout_ms = 200;
        e = cm_conn_open(&c, &io, &p, NULL);
        CHECK_TRUE(e == CM_ERR_TIMEOUT);
        cm_io_close(&io);
        close(sp[1]);
    }

    printf("test_conn: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

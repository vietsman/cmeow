/*
 * Smoke test for the client layer: (1) login flow against a scripted mock
 * server (pair-device QR event, success, prekey count/upload, passive,
 * CONNECTED); (2) Signal session between two cm_devices through the store
 * glue (prekey bundle -> pkmsg -> decrypt -> follow-up msg).
 */
#define _POSIX_C_SOURCE 200112L
#include "client.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <curve.h>
#include <protocol.h>
#include <session_builder.h>
#include <session_cipher.h>
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

/* ---- scripted server ---- */
static void send_node(struct srv *s, const cm_node *n)
{
    uint8_t *d;
    size_t l;

    if (cm_binary_marshal(n, &d, &l) == CM_OK) {
        srv_send_plain(s, d, l);
        free(d);
    }
}

static void reply_iq(struct srv *s, const cm_node *req, cm_node *content)
{
    cm_node r;
    cm_jid j;
    const cm_value *id = cm_node_get_attr(req, "id");

    cm_node_init(&r);
    cm_node_set_tag(&r, "iq");
    cm_node_set_attr_str(&r, "id", id->u.str);
    cm_node_set_attr_str(&r, "type", "result");
    cm_jid_init(&j);
    cm_jid_set(&j, "", "s.whatsapp.net");
    cm_node_set_attr_jid(&r, "from", &j);
    cm_jid_free(&j);
    if (content)
        cm_node_add_child(&r, content);
    send_node(s, &r);
    cm_node_free(&r);
}

static void script_ready(struct srv *s)
{
    cm_node n, pd, ref;
    cm_jid j;

    cm_node_init(&n); cm_node_set_tag(&n, "iq");
    cm_node_set_attr_str(&n, "id", "pd1");
    cm_node_set_attr_str(&n, "type", "set");
    cm_jid_init(&j); cm_jid_set(&j, "", "s.whatsapp.net");
    cm_node_set_attr_jid(&n, "from", &j);
    cm_jid_free(&j);
    cm_node_init(&pd); cm_node_set_tag(&pd, "pair-device");
    cm_node_init(&ref); cm_node_set_tag(&ref, "ref");
    cm_node_set_content_bytes(&ref, "REF1", 4);
    cm_node_add_child(&pd, &ref);
    cm_node_add_child(&n, &pd);
    send_node(s, &n);
    cm_node_free(&n);
}

static int g_uploads;

static void script_app(struct srv *s, const uint8_t *pt, size_t pl)
{
    uint8_t *raw;
    size_t rl;
    cm_node n;
    const char *type, *ns;

    cm_node_init(&n);
    if (cm_binary_unpack(pt, pl, &raw, &rl) != CM_OK)
        return;
    if (cm_binary_unmarshal(raw, rl, &n) != CM_OK) {
        free(raw);
        return;
    }
    free(raw);
    type = n.attrs ? cm_node_get_attr(&n, "type") ? cm_node_get_attr(&n, "type")->u.str : "" : "";
    ns = cm_node_get_attr(&n, "xmlns") ? cm_node_get_attr(&n, "xmlns")->u.str : "";
    if (strcmp(n.tag, "iq") == 0 && strcmp(type, "result") == 0) {
        /* ack of pair-device: now log in */
        cm_node ok;

        cm_node_init(&ok); cm_node_set_tag(&ok, "success");
        cm_node_set_attr_str(&ok, "t", "1700000000");
        send_node(s, &ok);
        cm_node_free(&ok);
    } else if (strcmp(n.tag, "iq") == 0 && strcmp(ns, "encrypt") == 0 && strcmp(type, "get") == 0) {
        cm_node c;

        cm_node_init(&c); cm_node_set_tag(&c, "count");
        cm_node_set_attr_str(&c, "value", "0");
        reply_iq(s, &n, &c);
    } else if (strcmp(n.tag, "iq") == 0 && strcmp(ns, "encrypt") == 0) {
        g_uploads = cm_node_nchildren(&n) == 5 ? 1 : -1; /* registration,type,identity,list,skey */
        if (cm_node_nchildren(&n) == 5) {
            const cm_node *list = cm_node_child(&n, "list");

            g_uploads = (list && cm_node_nchildren(list) == 812) ? 1 : -2;
        }
        reply_iq(s, &n, NULL);
    } else if (strcmp(n.tag, "iq") == 0 && strcmp(ns, "passive") == 0) {
        reply_iq(s, &n, NULL);
        wslay_event_queue_close(s->ev, WSLAY_CODE_NORMAL_CLOSURE, NULL, 0);
    }
    cm_node_free(&n);
}

/* ---- client side ---- */
static int got_qr, got_connected;
static char qr_text[256];

static void on_event(void *u, const cm_event *e)
{
    (void)u;
    if (e->type == CM_EVT_QR && !got_qr) {
        got_qr = 1;
        snprintf(qr_text, sizeof(qr_text), "%s", e->qr);
    } else if (e->type == CM_EVT_CONNECTED) {
        got_connected = 1;
    }
}

static void test_login_flow(void)
{
    struct server sv;
    int sp[2], status, i;
    pid_t pid;
    cm_device *dev;
    cm_client *c;
    cm_client_opts o;
    cm_io io;
    cm_jid me;

    make_server(&sv);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    pid = fork();
    if (pid == 0) {
        close(sp[0]);
        {
            int rc = server_main(sp[1], &sv, script_app, script_ready);

            _exit(rc ? rc : (g_uploads == 1 ? 0 : 9));
        }
    }
    close(sp[1]);
    io = cm_io_from_fd(sp[0]);

    CHECK_TRUE(cm_device_new(&dev) == CM_OK);
    cm_jid_init(&me);
    cm_jid_parse(&me, "15551234567:3@s.whatsapp.net");
    cm_device_set_id(dev, &me);
    cm_jid_free(&me);

    memset(&o, 0, sizeof(o));
    o.connect_io = &io;
    o.root_pub = sv.root.pub;
    o.timeout_ms = 5000;
    c = cm_client_new(dev, &o);
    CHECK_TRUE(c != NULL);
    cm_client_set_event_cb(c, on_event, NULL);
    CHECK_TRUE(cm_client_connect(c) == CM_OK);
    for (i = 0; i < 100; i++) {
        cm_err re = cm_client_run_once(c, 100);

        if (re != CM_OK) {
            fprintf(stderr, "run_once: %s after %d\n", cm_strerror(re), i);
            break;
        }
    }
    CHECK_TRUE(got_qr);
    CHECK_TRUE(strncmp(qr_text, "https://wa.me/settings/linked_devices#REF1,", 43) == 0);
    CHECK_TRUE(got_connected);
    cm_client_free(c);
    cm_device_free(dev);
    waitpid(pid, &status, 0);
    /* the child exits 0 only if it saw the initial 812-prekey upload */
    CHECK_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ---- store glue + libsignal between two devices ---- */
static void test_signal_roundtrip(void)
{
    cm_device *a, *b;
    cm_prekey *pks;
    uint32_t n;
    ec_public_key *ident = NULL, *spk = NULL, *pk = NULL;
    session_pre_key_bundle *bundle = NULL;
    session_builder *sb = NULL;
    session_cipher *ca = NULL, *cb = NULL;
    signal_protocol_address addr_b = {"bob", 3, 1}, addr_a = {"alice", 5, 1};
    ciphertext_message *ct = NULL, *ct2 = NULL;
    signal_buffer *s1, *pt = NULL, *pt2 = NULL;
    uint8_t k33[33];
    pre_key_signal_message *pkm = NULL;
    signal_message *sm = NULL;

    CHECK_TRUE(cm_device_new(&a) == CM_OK && cm_device_new(&b) == CM_OK);
    CHECK_TRUE(cm_device_get_or_gen_prekeys(b, 1, &pks, &n) == CM_OK && n == 1);
    k33[0] = 5; memcpy(k33 + 1, b->identity_key.pub, 32);
    CHECK_TRUE(curve_decode_point(&ident, k33, 33, a->sctx) >= 0);
    memcpy(k33 + 1, b->signed_prekey.key.pub, 32);
    CHECK_TRUE(curve_decode_point(&spk, k33, 33, a->sctx) >= 0);
    memcpy(k33 + 1, pks[0].key.pub, 32);
    CHECK_TRUE(curve_decode_point(&pk, k33, 33, a->sctx) >= 0);
    CHECK_TRUE(session_pre_key_bundle_create(&bundle, b->registration_id, 1, pks[0].id, pk,
                                             b->signed_prekey.id, spk, b->signed_prekey.signature, 64,
                                             ident) >= 0);
    CHECK_TRUE(session_builder_create(&sb, a->sstore, &addr_b, a->sctx) >= 0);
    CHECK_TRUE(session_builder_process_pre_key_bundle(sb, bundle) >= 0); /* verifies the XEdDSA signed-prekey sig */
    CHECK_TRUE(session_cipher_create(&ca, a->sstore, &addr_b, a->sctx) >= 0);
    CHECK_TRUE(session_cipher_encrypt(ca, (const uint8_t *)"hello bob", 9, &ct) >= 0);
    CHECK_TRUE(ciphertext_message_get_type(ct) == CIPHERTEXT_PREKEY_TYPE);
    s1 = ciphertext_message_get_serialized(ct);

    CHECK_TRUE(pre_key_signal_message_deserialize(&pkm, signal_buffer_data(s1), signal_buffer_len(s1), b->sctx) >= 0);
    CHECK_TRUE(session_cipher_create(&cb, b->sstore, &addr_a, b->sctx) >= 0);
    CHECK_TRUE(session_cipher_decrypt_pre_key_signal_message(cb, pkm, NULL, &pt) >= 0);
    CHECK_TRUE(pt && signal_buffer_len(pt) == 9 && memcmp(signal_buffer_data(pt), "hello bob", 9) == 0);
    CHECK_TRUE(cm_kvmap_find(&b->prekeys, "1") == NULL); /* one-time prekey consumed */

    /* reply, then a normal (non-prekey) message back to bob after the ratchet */
    CHECK_TRUE(session_cipher_encrypt(cb, (const uint8_t *)"hi alice", 8, &ct2) >= 0);
    CHECK_TRUE(ciphertext_message_get_type(ct2) == CIPHERTEXT_SIGNAL_TYPE);
    s1 = ciphertext_message_get_serialized(ct2);
    CHECK_TRUE(signal_message_deserialize(&sm, signal_buffer_data(s1), signal_buffer_len(s1), a->sctx) >= 0);
    CHECK_TRUE(session_cipher_decrypt_signal_message(ca, sm, NULL, &pt2) >= 0);
    CHECK_TRUE(pt2 && signal_buffer_len(pt2) == 8 && memcmp(signal_buffer_data(pt2), "hi alice", 8) == 0);

    /* persistence round trip keeps sessions */
    CHECK_TRUE(cm_device_save(a, "/tmp/cmeow_test_dev.bin") == CM_OK);
    {
        cm_device *a2 = NULL;

        CHECK_TRUE(cm_device_load(&a2, "/tmp/cmeow_test_dev.bin") == CM_OK);
        CHECK_TRUE(a2 && cm_kvmap_find(&a2->sessions, "bob.1") != NULL);
        CHECK_TRUE(a2 && memcmp(a2->identity_key.pub, a->identity_key.pub, 32) == 0);
        cm_device_free(a2);
        remove("/tmp/cmeow_test_dev.bin");
    }
    if (pt) signal_buffer_free(pt);
    if (pt2) signal_buffer_free(pt2);
    SIGNAL_UNREF(ct); SIGNAL_UNREF(ct2); SIGNAL_UNREF(pkm); SIGNAL_UNREF(sm);
    SIGNAL_UNREF(bundle); SIGNAL_UNREF(ident); SIGNAL_UNREF(spk); SIGNAL_UNREF(pk);
    session_builder_free(sb); session_cipher_free(ca); session_cipher_free(cb);
    free(pks);
    cm_device_free(a);
    cm_device_free(b);
}

int main(void)
{
    test_login_flow();
    test_signal_roundtrip();
    printf("test_client: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

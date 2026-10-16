/*
 * End-to-end test of cm_handshake_begin / cm_handshake_finish against a mock
 * server implemented here (the server half of Noise_XX plus a signed
 * certificate chain), including every certificate rejection path.
 */
#include "handshake.h"
#include "noise.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define CHECK_ERR(expr, want)                                                  \
    do {                                                                       \
        cm_err got__ = (expr);                                                 \
        g_checks++;                                                            \
        if (got__ != (want)) {                                                 \
            g_failed++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s -> %s (want %s)\n", __FILE__,      \
                    __LINE__, #expr, cm_strerror(got__), cm_strerror(want));   \
        }                                                                      \
    } while (0)


#include "mock_server.inc"

/* Runs a client handshake against the mock; returns the client's result. */
static cm_err run(const struct opts *o, const uint8_t *root_override, cm_hs_error *err,
                  int check_full, int64_t now)
{
    struct server sv;
    cm_keypair eph, noise_key;
    cm_handshake hs;
    uint8_t *hello, *shello, *finish = NULL;
    size_t hello_len, shello_len, finish_len = 0;
    cm_noise_transport tr;
    static const uint8_t payload[] = "client-payload-bytes-for-test";
    cm_err e;

    make_server(&sv);
    cm_keypair_generate(&eph);
    cm_keypair_generate(&noise_key);
    CHECK_ERR(cm_handshake_begin(&hs, &eph, &hello, &hello_len), CM_OK);

    /* ClientHello wire format: field 2 (LEN) { field 1 (LEN 32) } */
    if (check_full) {
        CHECK_TRUE(hello_len == 2 + 2 + 32);
        CHECK_TRUE(hello[0] == 0x12 && hello[1] == 0x22 && hello[2] == 0x0a && hello[3] == 0x20);
        CHECK_TRUE(memcmp(hello + 4, eph.pub, 32) == 0);
    }
    shello = server_hello(&sv, o, hello, hello_len, &shello_len, eph.pub);
    CHECK_TRUE(shello != NULL);
    e = cm_handshake_finish(&hs, shello, shello_len, &noise_key, payload, sizeof(payload) - 1, now,
                            root_override ? root_override : sv.root.pub, &finish, &finish_len, &tr, err);
    if (e == CM_OK && check_full) {
        /* the server can read what the client sent, and derives the same keys */
        WAWebProtobufsWa6__HandshakeMessage *fin =
            waweb_protobufs_wa6__handshake_message__unpack(NULL, finish_len, finish);
        uint8_t cli_static[32], plain[64];
        cm_noise_transport str;

        CHECK_TRUE(fin != NULL && fin->clientfinish != NULL);
        if (fin && fin->clientfinish) {
            CHECK_TRUE(fin->clientfinish->static_.len == 48);
            CHECK_ERR(cm_noise_decrypt(&sv.nh, fin->clientfinish->static_.data, 48, cli_static), CM_OK);
            CHECK_TRUE(memcmp(cli_static, noise_key.pub, 32) == 0);
            CHECK_ERR(cm_noise_mix_shared_secret(&sv.nh, sv.eph.priv, cli_static), CM_OK);
            CHECK_TRUE(fin->clientfinish->payload.len == sizeof(payload) - 1 + 16);
            CHECK_ERR(cm_noise_decrypt(&sv.nh, fin->clientfinish->payload.data,
                                       fin->clientfinish->payload.len, plain), CM_OK);
            CHECK_TRUE(memcmp(plain, payload, sizeof(payload) - 1) == 0);
            CHECK_TRUE(memcmp(sv.nh.hash, hs.nh.hash, 32) == 0);
            CHECK_ERR(cm_noise_finish(&sv.nh, &str), CM_OK);
            /* both sides derive the same (write, read) pair, as in whatsmeow */
            CHECK_TRUE(memcmp(str.write_key, tr.write_key, 32) == 0);
            CHECK_TRUE(memcmp(str.read_key, tr.read_key, 32) == 0);
            waweb_protobufs_wa6__handshake_message__free_unpacked(fin, NULL);
        }
    }
    free(hello);
    free(shello);
    free(finish);
    return e;
}

static void expect_fail(const struct opts *o, cm_err want, const char *msg_part, const char *label)
{
    cm_hs_error err;
    cm_err e;

    memset(&err, 0, sizeof(err));
    e = run(o, NULL, &err, 0, NOW);
    g_checks++;
    if (e != want || (msg_part && strstr(err.message, msg_part) == NULL)) {
        g_failed++;
        fprintf(stderr, "FAIL %s: got %s '%s' (want %s containing '%s')\n", label, cm_strerror(e),
                err.message, cm_strerror(want), msg_part ? msg_part : "");
    }
}

int main(void)
{
    struct opts o;
    cm_hs_error err;

    memset(&o, 0, sizeof(o));
    memset(&err, 0, sizeof(err));
    CHECK_ERR(run(&o, NULL, &err, 1, NOW), CM_OK);

    /* certificate / structure rejections, with whatsmeow's wording */
    memset(&o, 0, sizeof(o)); o.bad_inter_sig = 1;
    expect_fail(&o, CM_ERR_AUTH, "failed to verify intermediate cert signature", "bad_inter_sig");
    memset(&o, 0, sizeof(o)); o.bad_leaf_sig = 1;
    expect_fail(&o, CM_ERR_AUTH, "failed to verify intermediate cert signature", "bad_leaf_sig");
    memset(&o, 0, sizeof(o)); o.wrong_leaf_key = 1;
    expect_fail(&o, CM_ERR_AUTH, "cert key doesn't match decrypted static", "wrong_leaf_key");
    memset(&o, 0, sizeof(o)); o.wrong_issuer_serial = 1;
    expect_fail(&o, CM_ERR_AUTH, "unexpected leaf issuer serial", "wrong_issuer_serial");
    memset(&o, 0, sizeof(o)); o.inter_wrong_issuer = 1;
    expect_fail(&o, CM_ERR_AUTH, "unexpected intermediate issuer serial", "inter_wrong_issuer");
    memset(&o, 0, sizeof(o)); o.inter_not_before_future = 1;
    expect_fail(&o, CM_ERR_AUTH, "intermediate cert certificate not valid yet", "inter_future");
    memset(&o, 0, sizeof(o)); o.inter_expired = 1;
    expect_fail(&o, CM_ERR_AUTH, "intermediate cert certificate expired", "inter_expired");
    memset(&o, 0, sizeof(o)); o.leaf_not_before_future = 1;
    expect_fail(&o, CM_ERR_AUTH, "leaf cert cert certificate not valid yet", "leaf_future");
    memset(&o, 0, sizeof(o)); o.leaf_expired = 1;
    expect_fail(&o, CM_ERR_AUTH, "leaf cert cert certificate expired", "leaf_expired");
    memset(&o, 0, sizeof(o)); o.short_sig = 1;
    expect_fail(&o, CM_ERR_AUTH, "unexpected length of intermediate cert signature 63", "short_sig");
    memset(&o, 0, sizeof(o)); o.short_inter_key = 1;
    expect_fail(&o, CM_ERR_AUTH, "unexpected length of intermediate cert key 31", "short_inter_key");
    memset(&o, 0, sizeof(o)); o.missing_leaf = 1;
    expect_fail(&o, CM_ERR_PROTO, "missing parts of noise certificate", "missing_leaf");
    memset(&o, 0, sizeof(o)); o.garbage_cert = 1;
    expect_fail(&o, CM_ERR_PROTO, "failed to unmarshal noise certificate", "garbage_cert");
    memset(&o, 0, sizeof(o)); o.tamper_static = 1;
    expect_fail(&o, CM_ERR_AUTH, "failed to decrypt server static ciphertext", "tamper_static");
    memset(&o, 0, sizeof(o)); o.short_ephemeral = 1;
    expect_fail(&o, CM_ERR_PROTO, "missing parts of handshake response", "short_ephemeral");
    memset(&o, 0, sizeof(o)); o.no_static = 1;
    expect_fail(&o, CM_ERR_PROTO, "missing parts of handshake response", "no_static");
    memset(&o, 0, sizeof(o)); o.no_payload = 1;
    expect_fail(&o, CM_ERR_PROTO, "missing parts of handshake response", "no_payload");

    /* wrong root key => intermediate signature fails; real WA key rejects test chain */
    memset(&o, 0, sizeof(o));
    {
        cm_keypair other;
        cm_keypair_generate(&other);
        CHECK_ERR(run(&o, other.pub, &err, 0, NOW), CM_ERR_AUTH);
        CHECK_ERR(run(&o, cm_wa_cert_pubkey, &err, 0, NOW), CM_ERR_AUTH);
    }
    /* validity window edges: now == notBefore / notAfter is still valid */
    CHECK_ERR(run(&o, NULL, &err, 0, 1000), CM_OK);
    CHECK_ERR(run(&o, NULL, &err, 0, INT64_C(4000000000)), CM_OK);
    CHECK_ERR(run(&o, NULL, &err, 0, 999), CM_ERR_AUTH);
    CHECK_ERR(run(&o, NULL, &err, 0, INT64_C(4000000001)), CM_ERR_AUTH);

    /* malformed server hello frames */
    {
        cm_handshake hs;
        cm_keypair eph, nk;
        uint8_t *hello, *fin = NULL;
        size_t hl, fl;
        cm_noise_transport tr;
        static const uint8_t junk[] = {0xFF, 0xFF, 0xFF};

        cm_keypair_generate(&eph);
        cm_keypair_generate(&nk);
        CHECK_ERR(cm_handshake_begin(&hs, &eph, &hello, &hl), CM_OK);
        CHECK_ERR(cm_handshake_finish(&hs, junk, 3, &nk, (const uint8_t *)"x", 1, NOW, NULL, &fin, &fl, &tr, &err), CM_ERR_PROTO);
        CHECK_ERR(cm_handshake_finish(&hs, (const uint8_t *)"", 0, &nk, (const uint8_t *)"x", 1, NOW, NULL, &fin, &fl, &tr, &err), CM_ERR_PROTO);
        free(hello);
    }
    /* the XEdDSA wrapper on its own */
    {
        cm_keypair kp;
        uint8_t sig[64];
        CHECK_ERR(cm_keypair_generate(&kp), CM_OK);
        CHECK_ERR(cm_xeddsa_sign(kp.priv, "message", 7, sig), CM_OK);
        CHECK_ERR(cm_xeddsa_verify(kp.pub, "message", 7, sig), CM_OK);
        CHECK_ERR(cm_xeddsa_verify(kp.pub, "messagf", 7, sig), CM_ERR_AUTH);
        sig[63] ^= 0x80;
        CHECK_ERR(cm_xeddsa_verify(kp.pub, "message", 7, sig), CM_ERR_AUTH);
        CHECK_ERR(cm_xeddsa_sign(kp.priv, "", 0, sig), CM_OK);
        CHECK_ERR(cm_xeddsa_verify(kp.pub, "", 0, sig), CM_OK);
    }
    /* Known-answer vectors from the Signal Java/libsignal test-suite: OpenSSL X25519
     * must agree with libsignal's curve25519, and a signature produced by the
     * original implementation must verify through cm_xeddsa_verify. */
    {
        static const uint8_t alice_pub[33] = {
            0x05, 0x1b, 0xb7, 0x59, 0x66, 0xf2, 0xe9, 0x3a, 0x36, 0x91, 0xdf, 0xff, 0x94, 0x2b,
            0xb2, 0xa4, 0x66, 0xa1, 0xc0, 0x8b, 0x8d, 0x78, 0xca, 0x3f, 0x4d, 0x6d, 0xf8, 0xb8,
            0xbf, 0xa2, 0xe4, 0xee, 0x28};
        static const uint8_t alice_priv[32] = {
            0xc8, 0x06, 0x43, 0x9d, 0xc9, 0xd2, 0xc4, 0x76, 0xff, 0xed, 0x8f, 0x25, 0x80, 0xc0, 0x88,
            0x8d, 0x58, 0xab, 0x40, 0x6b, 0xf7, 0xae, 0x36, 0x98, 0x87, 0x90, 0x21, 0xb9, 0x6b, 0xb4,
            0xbf, 0x59};
        static const uint8_t bob_pub[33] = {
            0x05, 0x65, 0x36, 0x14, 0x99, 0x3d, 0x2b, 0x15, 0xee, 0x9e, 0x5f, 0xd3, 0xd8, 0x6c,
            0xe7, 0x19, 0xef, 0x4e, 0xc1, 0xda, 0xae, 0x18, 0x86, 0xa8, 0x7b, 0x3f, 0x5f, 0xa9,
            0x56, 0x5a, 0x27, 0xa2, 0x2f};
        static const uint8_t bob_priv[32] = {
            0xb0, 0x3b, 0x34, 0xc3, 0x3a, 0x1c, 0x44, 0xf2, 0x25, 0xb6, 0x62, 0xd2, 0xbf, 0x48, 0x59,
            0xb8, 0x13, 0x54, 0x11, 0xfa, 0x7b, 0x03, 0x86, 0xd4, 0x5f, 0xb7, 0x5d, 0xc5, 0xb9, 0x1b,
            0x44, 0x66};
        static const uint8_t shared[32] = {
            0x32, 0x5f, 0x23, 0x93, 0x28, 0x94, 0x1c, 0xed, 0x6e, 0x67, 0x3b, 0x86, 0xba, 0x41, 0x01,
            0x74, 0x48, 0xe9, 0x9b, 0x64, 0x9a, 0x9c, 0x38, 0x06, 0xc1, 0xdd, 0x7c, 0xa4, 0xc4, 0x77,
            0xe6, 0x29};
        static const uint8_t id_pub[33] = {
            0x05, 0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d, 0x9a, 0x1d, 0x80, 0x71, 0xdf, 0xe9,
            0xdc, 0xf8, 0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6, 0x35, 0x6b, 0xe8, 0x4d, 0x88, 0x7e,
            0x32, 0x2c, 0x64};
        static const uint8_t eph_pub[33] = {
            0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7, 0x8c, 0xb7, 0x25, 0x2e, 0x72, 0xc2, 0xc4,
            0xa5, 0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d, 0x50, 0x31, 0x18, 0xd1, 0xa8, 0x2d,
            0x99, 0xfb, 0x4a};
        static const uint8_t sig[64] = {
            0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11, 0x5d, 0xa7, 0x91, 0x09, 0xc6, 0x7c, 0x9c, 0x74,
            0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb, 0x8c, 0x63, 0xc2, 0x98, 0x4e, 0x28, 0x6d, 0xfb,
            0xed, 0xe8, 0x2d, 0xeb, 0x9d, 0xcd, 0x9f, 0xae, 0x0b, 0xfb, 0xb8, 0x21, 0x56, 0x9b, 0x3d, 0x90,
            0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86, 0xce, 0xf0, 0x47, 0xbd, 0x60, 0xb8, 0x6e, 0x88};
        cm_keypair a;
        uint8_t out[32], bad[64];

        CHECK_ERR(cm_keypair_from_private(&a, alice_priv), CM_OK);
        CHECK_TRUE(memcmp(a.pub, alice_pub + 1, 32) == 0);
        CHECK_ERR(cm_x25519(alice_priv, bob_pub + 1, out), CM_OK);
        CHECK_TRUE(memcmp(out, shared, 32) == 0);
        CHECK_ERR(cm_x25519(bob_priv, alice_pub + 1, out), CM_OK);
        CHECK_TRUE(memcmp(out, shared, 32) == 0);
        CHECK_ERR(cm_xeddsa_verify(id_pub + 1, eph_pub, 33, sig), CM_OK);
        memcpy(bad, sig, 64);
        bad[0] ^= 1;
        CHECK_ERR(cm_xeddsa_verify(id_pub + 1, eph_pub, 33, bad), CM_ERR_AUTH);
        CHECK_ERR(cm_xeddsa_verify(id_pub + 1, eph_pub, 32, sig), CM_ERR_AUTH);
    }
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

/*
 * Tests for the crypto wrappers, the Noise handshake / transport and the frame
 * parser.
 *
 */
#include "buf.h"
#include "crypto.h"
#include "noise.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* hex helpers */
static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = strlen(h) / 2, i;

    if (n > cap)
        return (size_t)-1;
    for (i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1)
            return (size_t)-1;
        out[i] = (uint8_t)v;
    }
    return n;
}

static int eq_hex(const uint8_t *got, size_t len, const char *want_hex)
{
    uint8_t want[8192];
    size_t n = unhex(want_hex, want, sizeof(want));

    return n == len && memcmp(got, want, len) == 0;
}

static uint8_t *seq(uint8_t start, size_t n)
{
    uint8_t *b = (uint8_t *)malloc(n ? n : 1);
    size_t i;

    for (i = 0; i < n; i++)
        b[i] = (uint8_t)(start + i * 7);
    return b;
}

/* ---- primitives against published vectors ---- */
static void test_primitives(void)
{
    uint8_t out[64], key[64], a[64], b[64];
    size_t n;

    /* SHA-256("abc"), FIPS 180-2 */
    CHECK_ERR(cm_sha256("abc", 3, out), CM_OK);
    CHECK_TRUE(eq_hex(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    /* SHA-256("") */
    CHECK_ERR(cm_sha256(NULL, 0, out), CM_OK);
    CHECK_TRUE(eq_hex(out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    /* two-part hashing == concatenation */
    CHECK_ERR(cm_sha256_2("a", 1, "bc", 2, out), CM_OK);
    CHECK_TRUE(eq_hex(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    /* RFC 4231 test case 1 */
    memset(key, 0x0b, 20);
    CHECK_ERR(cm_hmac_sha256(key, 20, "Hi There", 8, out), CM_OK);
    CHECK_TRUE(eq_hex(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    /* RFC 4231 test case 2 */
    CHECK_ERR(cm_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, out), CM_OK);
    CHECK_TRUE(eq_hex(out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    /* RFC 5869 test case 1 */
    memset(key, 0x0b, 22);
    n = unhex("000102030405060708090a0b0c", a, sizeof(a));
    unhex("f0f1f2f3f4f5f6f7f8f9", b, sizeof(b));
    CHECK_ERR(cm_hkdf_sha256(key, 22, a, n, b, 10, out, 42), CM_OK);
    CHECK_TRUE(eq_hex(out, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                               "34007208d5b887185865"));
    /* RFC 5869 test case 3: empty salt and info */
    CHECK_ERR(cm_hkdf_sha256(key, 22, NULL, 0, NULL, 0, out, 42), CM_OK);
    CHECK_TRUE(eq_hex(out, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                               "9d201395faa4b61a96c8"));
    CHECK_ERR(cm_hkdf_sha256(key, 22, NULL, 0, NULL, 0, out, 255 * 32 + 1), CM_ERR_ARG);
    CHECK_ERR(cm_hkdf_sha256(key, 22, NULL, 0, NULL, 0, out, 0), CM_OK);

    /* RFC 7748 section 5.2, first X25519 vector */
    {
        uint8_t k[32], u[32], r[32];
        unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32);
        unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
        CHECK_ERR(cm_x25519(k, u, r), CM_OK);
        CHECK_TRUE(eq_hex(r, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    }
    /* RFC 7748 section 6.1 Diffie-Hellman */
    {
        cm_keypair alice, bob;
        uint8_t ap[32], bp[32], s1[32], s2[32];
        unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", ap, 32);
        unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bp, 32);
        CHECK_ERR(cm_keypair_from_private(&alice, ap), CM_OK);
        CHECK_ERR(cm_keypair_from_private(&bob, bp), CM_OK);
        CHECK_TRUE(eq_hex(alice.pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        CHECK_TRUE(eq_hex(bob.pub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        CHECK_ERR(cm_x25519(alice.priv, bob.pub, s1), CM_OK);
        CHECK_ERR(cm_x25519(bob.priv, alice.pub, s2), CM_OK);
        CHECK_TRUE(memcmp(s1, s2, 32) == 0);
        CHECK_TRUE(eq_hex(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    }
    /* all-zero public key is a low order point: must be rejected */
    {
        uint8_t k[32], zero[32], r[32];
        memset(k, 7, 32);
        memset(zero, 0, 32);
        CHECK_ERR(cm_x25519(k, zero, r), CM_ERR_CRYPTO);
    }
    /* generated keys are clamped and consistent */
    {
        cm_keypair kp, kp2;
        CHECK_ERR(cm_keypair_generate(&kp), CM_OK);
        CHECK_TRUE((kp.priv[0] & 7) == 0 && (kp.priv[31] & 0x80) == 0 && (kp.priv[31] & 0x40) != 0);
        CHECK_ERR(cm_keypair_from_private(&kp2, kp.priv), CM_OK);
        CHECK_TRUE(memcmp(kp.pub, kp2.pub, 32) == 0);
    }

    /* AES-256-GCM: round trip, tamper detection, aliasing, edge sizes */
    {
        uint8_t k[32], iv[12], aad[20];
        size_t sizes[] = {0, 1, 15, 16, 17, 1000};
        size_t i;

        memset(k, 0x42, 32);
        memset(iv, 0x24, 12);
        memset(aad, 0x99, 20);
        for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            size_t len = sizes[i];
            uint8_t *pt = seq(3, len), *ct = (uint8_t *)malloc(len + 16), *back = (uint8_t *)malloc(len + 1);

            CHECK_ERR(cm_aes256gcm_seal(k, iv, aad, 20, pt, len, ct), CM_OK);
            CHECK_ERR(cm_aes256gcm_open(k, iv, aad, 20, ct, len + 16, back), CM_OK);
            CHECK_TRUE(len == 0 || memcmp(back, pt, len) == 0);
            /* wrong aad / wrong iv / flipped bit / truncated tag all fail with AUTH */
            CHECK_ERR(cm_aes256gcm_open(k, iv, aad, 19, ct, len + 16, back), CM_ERR_AUTH);
            iv[0] ^= 1;
            CHECK_ERR(cm_aes256gcm_open(k, iv, aad, 20, ct, len + 16, back), CM_ERR_AUTH);
            iv[0] ^= 1;
            ct[len + 15] ^= 1;
            CHECK_ERR(cm_aes256gcm_open(k, iv, aad, 20, ct, len + 16, back), CM_ERR_AUTH);
            ct[len + 15] ^= 1;
            if (len) {
                ct[0] ^= 0x80;
                CHECK_ERR(cm_aes256gcm_open(k, iv, aad, 20, ct, len + 16, back), CM_ERR_AUTH);
                /* failed open must not leak plaintext */
                CHECK_TRUE(back[0] == 0);
                ct[0] ^= 0x80;
            }
            /* in-place open */
            CHECK_ERR(cm_aes256gcm_open(k, iv, aad, 20, ct, len + 16, ct), CM_OK);
            CHECK_TRUE(len == 0 || memcmp(ct, pt, len) == 0);
            free(pt);
            free(ct);
            free(back);
        }
        CHECK_ERR(cm_aes256gcm_open(k, iv, NULL, 0, "short", 5, out), CM_ERR_AUTH);
    }
    CHECK_TRUE(cm_ct_equal("abc", "abc", 3) && !cm_ct_equal("abc", "abd", 3));
}

/* ---- frame parser ---- */
struct frames {
    size_t count;
    size_t lens[16];
    uint32_t sums[16];
    int stop_after;
};

static uint32_t fsum(const uint8_t *p, size_t n)
{
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static cm_err on_frame(void *user, const uint8_t *f, size_t n)
{
    struct frames *fr = (struct frames *)user;

    if (fr->count < 16) {
        fr->lens[fr->count] = n;
        fr->sums[fr->count] = fsum(f, n);
    }
    fr->count++;
    if (fr->stop_after && (int)fr->count >= fr->stop_after)
        return CM_ERR_CLOSED;
    return CM_OK;
}

static void test_frames(void)
{
    static const size_t plens[] = {0, 1, 2, 300, 70000};
    size_t nframes = sizeof(plens) / sizeof(plens[0]), i, total = 0, chunk;
    cm_buf wire;
    uint8_t hdr[4];
    uint8_t *payloads[5];
    uint32_t sums[5];

    cm_conn_header(hdr);
    CHECK_TRUE(hdr[0] == 'W' && hdr[1] == 'A' && hdr[2] == 6 && hdr[3] == 3);

    cm_buf_init(&wire);
    for (i = 0; i < nframes; i++) {
        payloads[i] = seq((uint8_t)(i * 13 + 1), plens[i]);
        sums[i] = fsum(payloads[i], plens[i]);
        /* only the first frame carries the connection header, like FrameSocket */
        CHECK_ERR(cm_frame_encode(&wire, i == 0 ? hdr : NULL, 4, payloads[i], plens[i]), CM_OK);
        total += 3 + plens[i];
    }
    CHECK_TRUE(wire.len == total + 4);
    CHECK_TRUE(memcmp(wire.data, hdr, 4) == 0);
    CHECK_TRUE(wire.data[4] == 0 && wire.data[5] == 0 && wire.data[6] == 0); /* frame 0: len 0 */

    /* The peer's frames have no connection header: parse the wire minus it. */
    {
        const uint8_t *stream = wire.data + 4;
        size_t slen = wire.len - 4;
        static const size_t chunks[] = {1, 2, 3, 4, 5, 7, 64, 1000, 4096, 70000, 200000};

        for (chunk = 0; chunk < sizeof(chunks) / sizeof(chunks[0]); chunk++) {
            cm_frame_parser p;
            struct frames fr;
            size_t off = 0;

            memset(&fr, 0, sizeof(fr));
            cm_frame_parser_init(&p);
            while (off < slen) {
                size_t take = slen - off < chunks[chunk] ? slen - off : chunks[chunk];
                CHECK_ERR(cm_frame_parser_feed(&p, stream + off, take, on_frame, &fr), CM_OK);
                off += take;
            }
            CHECK_TRUE(fr.count == nframes);
            for (i = 0; i < nframes && i < fr.count; i++) {
                CHECK_TRUE(fr.lens[i] == plens[i]);
                CHECK_TRUE(fr.sums[i] == sums[i]);
            }
            cm_frame_parser_free(&p);
        }
        /* a callback error aborts parsing and is propagated */
        {
            cm_frame_parser p;
            struct frames fr;

            memset(&fr, 0, sizeof(fr));
            fr.stop_after = 2;
            cm_frame_parser_init(&p);
            CHECK_ERR(cm_frame_parser_feed(&p, stream, slen, on_frame, &fr), CM_ERR_CLOSED);
            CHECK_TRUE(fr.count == 2);
            cm_frame_parser_free(&p);
        }
        /* truncated stream: no frame emitted for the partial one, no leak on free */
        {
            cm_frame_parser p;
            struct frames fr;

            memset(&fr, 0, sizeof(fr));
            cm_frame_parser_init(&p);
            CHECK_ERR(cm_frame_parser_feed(&p, stream, slen - 5, on_frame, &fr), CM_OK);
            CHECK_TRUE(fr.count == nframes - 1);
            cm_frame_parser_free(&p);
        }
    }
    for (i = 0; i < nframes; i++)
        free(payloads[i]);
    cm_buf_free(&wire);

    /* size limits: 2^24 - 1 fits, 2^24 does not */
    {
        cm_buf b;
        uint8_t *big = (uint8_t *)calloc(CM_FRAME_MAX_SIZE, 1);

        cm_buf_init(&b);
        CHECK_ERR(cm_frame_encode(&b, NULL, 0, big, CM_FRAME_MAX_SIZE - 1), CM_OK);
        CHECK_TRUE(b.len == 3 + CM_FRAME_MAX_SIZE - 1 && b.data[0] == 0xFF && b.data[2] == 0xFF);
        cm_buf_free(&b);
        CHECK_ERR(cm_frame_encode(&b, NULL, 0, big, CM_FRAME_MAX_SIZE), CM_ERR_TOO_LARGE);
        CHECK_TRUE(b.len == 0);
        free(big);
    }
}

/* ---- noise: self-consistency between two roles ---- */
static void test_noise_roundtrip(void)
{
    cm_noise_hs c, s;
    cm_keypair ce, cs, se, ss;
    uint8_t hdr[4], ct[200], pt[200], sct[300], spt[300];
    cm_noise_transport ct_c, ct_s;
    uint8_t secret_c[32], secret_s[32];

    cm_conn_header(hdr);
    CHECK_ERR(cm_keypair_generate(&ce), CM_OK);
    CHECK_ERR(cm_keypair_generate(&cs), CM_OK);
    CHECK_ERR(cm_keypair_generate(&se), CM_OK);
    CHECK_ERR(cm_keypair_generate(&ss), CM_OK);

    CHECK_ERR(cm_noise_start(&c, CM_NOISE_START_PATTERN, CM_NOISE_START_PATTERN_LEN, hdr, 4), CM_OK);
    CHECK_ERR(cm_noise_start(&s, CM_NOISE_START_PATTERN, CM_NOISE_START_PATTERN_LEN, hdr, 4), CM_OK);
    CHECK_TRUE(memcmp(c.hash, s.hash, 32) == 0);
    cm_noise_authenticate(&c, ce.pub, 32);
    cm_noise_authenticate(&s, ce.pub, 32);
    cm_noise_authenticate(&c, se.pub, 32);
    cm_noise_authenticate(&s, se.pub, 32);
    CHECK_ERR(cm_noise_mix_shared_secret(&c, ce.priv, se.pub), CM_OK);
    CHECK_ERR(cm_noise_mix_shared_secret(&s, se.priv, ce.pub), CM_OK);
    CHECK_TRUE(memcmp(c.salt, s.salt, 32) == 0 && memcmp(c.key, s.key, 32) == 0);

    CHECK_ERR(cm_noise_encrypt(&s, ss.pub, 32, ct), CM_OK);
    CHECK_ERR(cm_noise_decrypt(&c, ct, 48, pt), CM_OK);
    CHECK_TRUE(memcmp(pt, ss.pub, 32) == 0 && memcmp(c.hash, s.hash, 32) == 0);
    /* tampered ciphertext is rejected and does NOT advance the hash */
    {
        cm_noise_hs c2 = c, s2 = s;
        uint8_t before[32];

        CHECK_ERR(cm_noise_encrypt(&s2, "payload", 7, ct), CM_OK);
        ct[0] ^= 1;
        memcpy(before, c2.hash, 32);
        CHECK_ERR(cm_noise_decrypt(&c2, ct, 7 + 16, pt), CM_ERR_AUTH);
        CHECK_TRUE(memcmp(before, c2.hash, 32) == 0);
        CHECK_TRUE(c2.counter == 2); /* was 1; advances even on failure, like Go */
    }
    CHECK_ERR(cm_noise_mix_shared_secret(&c, ce.priv, ss.pub), CM_OK);
    CHECK_ERR(cm_noise_mix_shared_secret(&s, ss.priv, ce.pub), CM_OK);
    CHECK_ERR(cm_noise_encrypt(&c, cs.pub, 32, ct), CM_OK);
    CHECK_ERR(cm_noise_decrypt(&s, ct, 48, pt), CM_OK);
    CHECK_ERR(cm_noise_mix_shared_secret(&c, cs.priv, se.pub), CM_OK);
    CHECK_ERR(cm_noise_mix_shared_secret(&s, se.priv, cs.pub), CM_OK);
    CHECK_TRUE(memcmp(c.hash, s.hash, 32) == 0 && memcmp(c.salt, s.salt, 32) == 0);

    CHECK_ERR(cm_noise_finish(&c, &ct_c), CM_OK);
    CHECK_ERR(cm_noise_finish(&s, &ct_s), CM_OK);
    /* client's write key is the server's... Go derives (write, read) the same
     * way on both sides, so they are NOT swapped; document that by testing it */
    CHECK_TRUE(memcmp(ct_c.write_key, ct_s.write_key, 32) == 0);
    memset(secret_c, 1, 32);
    memset(secret_s, 2, 32);

    /* transport: both directions, counters advance, replay/out-of-order fails */
    {
        uint8_t m1[] = "hello", m2[] = "world!";
        cm_noise_transport rx = ct_s; /* "peer" decrypts with the same write key */

        /* in whatsmeow the peer would hold the roles swapped; model that */
        memcpy(rx.read_key, ct_c.write_key, 32);
        CHECK_ERR(cm_noise_transport_seal(&ct_c, m1, 5, sct), CM_OK);
        CHECK_ERR(cm_noise_transport_seal(&ct_c, m2, 6, sct + 21), CM_OK);
        CHECK_TRUE(ct_c.write_counter == 2);
        CHECK_ERR(cm_noise_transport_open(&rx, sct + 21, 22, spt), CM_ERR_AUTH); /* wrong order */
        rx.read_counter = 0;
        CHECK_ERR(cm_noise_transport_open(&rx, sct, 21, spt), CM_OK);
        CHECK_TRUE(memcmp(spt, "hello", 5) == 0 && rx.read_counter == 1);
        CHECK_ERR(cm_noise_transport_open(&rx, sct + 21, 22, spt), CM_OK);
        CHECK_TRUE(memcmp(spt, "world!", 6) == 0 && rx.read_counter == 2);
    }
    (void)secret_c;
    (void)secret_s;
}

int main(void)
{
    test_primitives();
    test_frames();
    test_noise_roundtrip();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

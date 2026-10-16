/*
 * Tests for the binary XML codec, JID type and node tree.
 *
 * Self-contained: no external vectors or toolchains needed.
 */
#include "binary.h"
#include "buf.h"
#include "jid.h"
#include "node.h"
#include "token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static int g_failed;
static int g_checks;

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

/* ---- helpers ---- */

static void fill_pat(uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        b[i] = (uint8_t)(i * 31 + 7);
}

/* ---- tests ---- */

static void test_tokens(void)
{
    size_t i;
    int d;
    uint8_t idx, dict;

    CHECK_TRUE(cm_single_token_count == 236);
    CHECK_TRUE(cm_dict_version == 3);
    CHECK_TRUE(strcmp(cm_single_tokens[3], "s.whatsapp.net") == 0);
    CHECK_TRUE(strcmp(cm_single_tokens[0], "") == 0);
    for (d = 0; d < 4; d++)
        CHECK_TRUE(cm_double_dicts[d].count == 256);
    CHECK_TRUE(cm_token_get_double(4, 0) == NULL);
    CHECK_TRUE(cm_token_get_double(0, 256) == NULL);
    CHECK_TRUE(cm_token_get_double(-1, 0) == NULL);
    CHECK_TRUE(strcmp(cm_token_get_double(0, 0), "read-self") == 0);

    /* every non-empty single token resolves back to an index holding it */
    for (i = 1; i < cm_single_token_count; i++) {
        CHECK_TRUE(cm_token_index_single(cm_single_tokens[i], &idx));
        CHECK_TRUE(strcmp(cm_single_tokens[idx], cm_single_tokens[i]) == 0);
    }
    for (d = 0; d < 4; d++) {
        for (i = 0; i < cm_double_dicts[d].count; i++) {
            const char *t = cm_double_dicts[d].tokens[i];
            CHECK_TRUE(cm_token_index_double(t, &dict, &idx));
            CHECK_TRUE(strcmp(cm_token_get_double(dict, idx), t) == 0);
        }
    }
    CHECK_TRUE(!cm_token_index_single("definitely-not-a-token", &idx));
    CHECK_TRUE(!cm_token_index_single("", &idx));
    CHECK_TRUE(!cm_token_index_double("definitely-not-a-token", &dict, &idx));
}


static void test_jid_manual(void)
{
    cm_jid j;
    char *s;

    cm_jid_init(&j);
    CHECK_ERR(cm_jid_parse(&j, "1234.1:7@s.whatsapp.net"), CM_OK);
    CHECK_TRUE(strcmp(cm_jid_user(&j), "1234") == 0);
    CHECK_TRUE(j.raw_agent == 1 && j.device == 7);
    CHECK_ERR(cm_jid_to_string(&j, &s), CM_OK);
    CHECK_TRUE(strcmp(s, "1234.1:7@s.whatsapp.net") == 0);
    free(s);
    CHECK_ERR(cm_jid_parse(&j, "1.2.3@x"), CM_ERR_INVALID_JID);
    CHECK_ERR(cm_jid_set_ad(&j, "99", CM_DOMAIN_LID, 4), CM_OK);
    CHECK_TRUE(strcmp(cm_jid_server(&j), "lid") == 0 && j.raw_agent == 0 && j.device == 4);
    CHECK_ERR(cm_jid_signal_address_user(&j, &s), CM_OK);
    CHECK_TRUE(strcmp(s, "99_1") == 0);
    free(s);
    cm_jid_free(&j);
}

static void test_node_api(void)
{
    cm_node n, c, copy;
    const cm_value *v;
    cm_jid j;
    uint8_t *b1, *b2;
    size_t l1, l2;

    cm_node_init(&n);
    cm_node_init(&c);
    cm_node_init(&copy);
    CHECK_ERR(cm_node_set_tag(&n, "iq"), CM_OK);
    CHECK_ERR(cm_node_set_attr_str(&n, "type", "get"), CM_OK);
    CHECK_ERR(cm_node_set_attr_str(&n, "type", "set"), CM_OK); /* replaces */
    CHECK_TRUE(n.nattrs == 1);
    v = cm_node_get_attr(&n, "type");
    CHECK_TRUE(v && v->type == CM_V_STR && strcmp(v->u.str, "set") == 0);
    CHECK_TRUE(cm_node_get_attr(&n, "nope") == NULL);
    cm_jid_init(&j);
    CHECK_ERR(cm_jid_parse(&j, "123@s.whatsapp.net"), CM_OK);
    CHECK_ERR(cm_node_set_attr_jid(&n, "to", &j), CM_OK);
    cm_jid_free(&j);
    CHECK_ERR(cm_node_set_attr_i64(&n, "t", -5), CM_OK);
    CHECK_ERR(cm_node_set_attr_u64(&n, "u", UINT64_C(18446744073709551615)), CM_OK);
    CHECK_ERR(cm_node_set_attr_bool(&n, "b", 1), CM_OK);
    CHECK_TRUE(strcmp(cm_node_get_attr(&n, "u")->u.str, "18446744073709551615") == 0);
    CHECK_TRUE(strcmp(cm_node_get_attr(&n, "b")->u.str, "true") == 0);

    CHECK_ERR(cm_node_set_tag(&c, "ping"), CM_OK);
    CHECK_ERR(cm_node_add_child(&n, &c), CM_OK);
    CHECK_TRUE(c.tag == NULL); /* moved */
    CHECK_TRUE(cm_node_nchildren(&n) == 1);
    CHECK_TRUE(cm_node_child(&n, "ping") != NULL);
    CHECK_TRUE(cm_node_child(&n, "pong") == NULL);
    CHECK_TRUE(cm_node_child_at(&n, 1) == NULL);
    CHECK_ERR(cm_node_set_content_str(&c, "x"), CM_OK);
    CHECK_ERR(cm_node_add_child(&c, &n), CM_ERR_INVALID_TYPE); /* content is a string */
    cm_node_free(&c);

    CHECK_ERR(cm_node_clone(&copy, &n), CM_OK);
    CHECK_ERR(cm_binary_marshal(&n, &b1, &l1), CM_OK);
    CHECK_ERR(cm_binary_marshal(&copy, &b2, &l2), CM_OK);
    CHECK_TRUE(l1 == l2 && memcmp(b1, b2, l1) == 0);
    free(b1);
    free(b2);
    cm_node_free(&n);
    cm_node_free(&copy);
}

static cm_node mk(const char *tag)
{
    cm_node n;
    cm_node_init(&n);
    cm_node_set_tag(&n, tag);
    return n;
}

static void test_handcrafted(void)
{
    cm_node n = mk("x"), out;
    uint8_t *enc;
    size_t len;

    cm_node_init(&out);

    /* <iq to="s.whatsapp.net"/> : LIST8 3, token iq(25), token to(17), token s.whatsapp.net(3) wrapped as JID pair */
    {
        cm_jid j;
        cm_node_free(&n);
        n = mk("iq");
        cm_jid_init(&j);
        cm_jid_set(&j, "", "s.whatsapp.net");
        cm_node_set_attr_jid(&n, "to", &j);
        cm_jid_free(&j);
        CHECK_ERR(cm_binary_marshal(&n, &enc, &len), CM_OK);
        {
            static const uint8_t want[] = {0x00, 0xF8, 0x03, 25, 17, 0xFA, 0x00, 3};
            CHECK_TRUE(len == sizeof(want) && memcmp(enc, want, len) == 0);
        }
        free(enc);
        cm_node_free(&n);
    }

    /* error classes */
    {
        static const uint8_t empty_list[] = {0xF8, 0x00};
        static const uint8_t bad_tag[] = {0xF8, 0x01, 0xF0};        /* token 240 undefined */
        static const uint8_t trailing[] = {0xF8, 0x01, 25, 0x99};
        static const uint8_t nonstr_key[] = {0xF8, 0x03, 25, 0xF8, 0x01, 0xF8, 0x01, 25, 3}; /* key is a list */
        static const uint8_t nibble_bad[] = {0xF8, 0x03, 25, 17, 0xFF, 0x01, 0xC0};
        static const uint8_t odd_zero[] = {0xF8, 0x03, 25, 17, 0xFF, 0x80};
        static const uint8_t pair_nil_server[] = {0xF8, 0x03, 25, 17, 0xFA, 0x00, 0x00};
        static const uint8_t nul_in_string[] = {0xF8, 0x03, 25, 17, 0xFC, 0x03, 'a', 0, 'b'};
        static const uint8_t huge_binary[] = {0xF8, 0x02, 25, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t huge_list[] = {0xF8, 0x02, 25, 0xF9, 0xFF, 0xFF};
        static const uint8_t dup_attr[] = {0xF8, 0x05, 25, 17, 3, 17, 4};
        static const uint8_t empty_tag[] = {0xF8, 0x01, 0xFC, 0x00};

        CHECK_ERR(cm_binary_unmarshal(empty_list, sizeof(empty_list), &out), CM_ERR_EOF);
        CHECK_ERR(cm_binary_unmarshal(bad_tag, sizeof(bad_tag), &out), CM_ERR_INVALID_TOKEN);
        CHECK_ERR(cm_binary_unmarshal(trailing, sizeof(trailing), &out), CM_ERR_TRAILING_DATA);
        CHECK_ERR(cm_binary_unmarshal(nonstr_key, sizeof(nonstr_key), &out), CM_ERR_NON_STRING_KEY);
        CHECK_ERR(cm_binary_unmarshal(nibble_bad, sizeof(nibble_bad), &out), CM_ERR_INVALID_TOKEN);
        CHECK_ERR(cm_binary_unmarshal(odd_zero, sizeof(odd_zero), &out), CM_ERR_INVALID_TOKEN);
        CHECK_ERR(cm_binary_unmarshal(pair_nil_server, sizeof(pair_nil_server), &out), CM_ERR_INVALID_JID_TYPE);
        CHECK_ERR(cm_binary_unmarshal(nul_in_string, sizeof(nul_in_string), &out), CM_ERR_INVALID_TOKEN);
        CHECK_ERR(cm_binary_unmarshal(huge_binary, sizeof(huge_binary), &out), CM_ERR_EOF);
        CHECK_ERR(cm_binary_unmarshal(huge_list, sizeof(huge_list), &out), CM_ERR_EOF);
        CHECK_ERR(cm_binary_unmarshal(empty_tag, sizeof(empty_tag), &out), CM_ERR_INVALID_NODE);
        CHECK_ERR(cm_binary_unmarshal(NULL, 0, &out), CM_ERR_EOF);

        /* duplicate attribute keys: last one wins, like a Go map */
        CHECK_ERR(cm_binary_unmarshal(dup_attr, sizeof(dup_attr), &out), CM_OK);
        CHECK_TRUE(out.nattrs == 1);
        CHECK_TRUE(strcmp(cm_node_get_attr(&out, "to")->u.str, "4") == 0 ||
                   strcmp(cm_node_get_attr(&out, "to")->u.str, cm_single_tokens[4]) == 0);
        cm_node_free(&out);
    }

    /* nesting depth bomb must fail cleanly, not overflow the stack */
    {
        size_t levels = 5000, i, p = 0;
        uint8_t *bomb = (uint8_t *)malloc(levels * 5 + 8);

        for (i = 0; i < levels; i++) {
            bomb[p++] = 0xF8; bomb[p++] = 0x02; bomb[p++] = 25; /* node iq with content */
            bomb[p++] = 0xF8; bomb[p++] = 0x01;                /* list of 1 */
        }
        bomb[p++] = 0xF8; bomb[p++] = 0x01; bomb[p++] = 25;
        CHECK_ERR(cm_binary_unmarshal(bomb, p, &out), CM_ERR_DEPTH);
        free(bomb);
    }
    {
        size_t i, p = 0;
        uint8_t *bomb = (uint8_t *)malloc(100000);
        bomb[p++] = 0xF8; bomb[p++] = 0x03; bomb[p++] = 25; bomb[p++] = 17; /* <iq to=... */
        for (i = 0; i < 90000; i++)
            bomb[p++] = 0xFA; /* JID pair inside JID pair ... */
        CHECK_ERR(cm_binary_unmarshal(bomb, p, &out), CM_ERR_DEPTH);
        free(bomb);
    }

    /* decoded strings vs bytes: tokens are strings, raw content is bytes */
    {
        static const uint8_t raw_content[] = {0xF8, 0x02, 25, 0xFC, 0x02, 'h', 'i'};
        static const uint8_t tok_content[] = {0xF8, 0x02, 25, 3};
        CHECK_ERR(cm_binary_unmarshal(raw_content, sizeof(raw_content), &out), CM_OK);
        CHECK_TRUE(out.content.type == CM_V_BYTES && out.content.u.bytes.len == 2);
        cm_node_free(&out);
        CHECK_ERR(cm_binary_unmarshal(tok_content, sizeof(tok_content), &out), CM_OK);
        CHECK_TRUE(out.content.type == CM_V_STR && strcmp(out.content.u.str, "s.whatsapp.net") == 0);
        cm_node_free(&out);
    }
}

static void test_unpack(void)
{
    static const uint8_t plain[] = {0x00, 1, 2, 3};
    uint8_t *out, *z;
    size_t outlen;
    uint8_t payload[4096];
    uLongf zlen;
    size_t i;

    CHECK_ERR(cm_binary_unpack(plain, sizeof(plain), &out, &outlen), CM_OK);
    CHECK_TRUE(outlen == 3 && out[0] == 1 && out[2] == 3);
    free(out);
    CHECK_ERR(cm_binary_unpack(plain, 0, &out, &outlen), CM_ERR_EOF);
    CHECK_ERR(cm_binary_unpack(plain, 1, &out, &outlen), CM_OK);
    CHECK_TRUE(outlen == 0);
    free(out);

    for (i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)((i * i) >> 3);
    zlen = compressBound(sizeof(payload));
    z = (uint8_t *)malloc(zlen + 1);
    CHECK_TRUE(compress(z + 1, &zlen, payload, sizeof(payload)) == Z_OK);
    z[0] = 2;
    CHECK_ERR(cm_binary_unpack(z, zlen + 1, &out, &outlen), CM_OK);
    CHECK_TRUE(outlen == sizeof(payload) && memcmp(out, payload, outlen) == 0);
    free(out);
    /* trailing garbage after the zlib stream is ignored, like Go */
    z = (uint8_t *)realloc(z, zlen + 9);
    memset(z + zlen + 1, 0xAA, 8);
    CHECK_ERR(cm_binary_unpack(z, zlen + 9, &out, &outlen), CM_OK);
    CHECK_TRUE(outlen == sizeof(payload));
    free(out);
    /* truncated and corrupt streams */
    CHECK_ERR(cm_binary_unpack(z, zlen / 2, &out, &outlen), CM_ERR_ZLIB);
    z[5] ^= 0xFF;
    CHECK_ERR(cm_binary_unpack(z, zlen + 1, &out, &outlen), CM_ERR_ZLIB);
    free(z);
}

static void test_encoder_limits(void)
{
    cm_node n = mk("zz"), c;
    uint8_t *enc;
    size_t len, i;
    cm_node out;

    /* encoder skips nil and empty-string attributes */
    cm_node_set_attr_str(&n, "a", "");
    {
        cm_value nv;
        cm_value_init(&nv);
        cm_node_set_attr_value(&n, "b", &nv);
    }
    CHECK_ERR(cm_binary_marshal(&n, &enc, &len), CM_OK);
    {
        /* LIST_8 1, raw tag "zz" (BINARY_8 2 'z' 'z') */
        static const uint8_t want[] = {0x00, 0xF8, 0x01, 0xFC, 0x02, 'z', 'z'};
        CHECK_TRUE(len == sizeof(want) && memcmp(enc, want, len) == 0);
    }
    free(enc);

    /* a node with no tag cannot be encoded */
    {
        cm_node bad;
        cm_node_init(&bad);
        CHECK_ERR(cm_binary_marshal(&bad, &enc, &len), CM_ERR_INVALID_NODE);
    }
    CHECK_ERR(cm_binary_marshal(NULL, &enc, &len), CM_ERR_ARG);

    /* > 65535 children cannot be expressed as a List16 */
    for (i = 0; i < 65536; i++) {
        cm_node_init(&c);
        cm_node_set_tag(&c, "c");
        if (cm_node_add_child(&n, &c) != CM_OK)
            break;
    }
    CHECK_ERR(cm_binary_marshal(&n, &enc, &len), CM_ERR_TOO_LARGE);
    cm_node_free(&n);

    /* decoded empty list content (List8 0) is an empty node list */
    cm_node_init(&out);
    {
        static const uint8_t el[] = {0xF8, 0x02, 25, 0xF8, 0x00};
        CHECK_ERR(cm_binary_unmarshal(el, sizeof(el), &out), CM_OK);
        CHECK_TRUE(out.content.type == CM_V_NODES && out.content.u.nodes.len == 0);
        cm_node_free(&out);
    }
}

/* Deterministic mutation fuzzing: must never crash or leak (run under ASan). */
static cm_err build_fuzz_seed(int which, cm_node *n)
{
    cm_jid j;
    cm_err e;

    cm_node_init(n);
    cm_jid_init(&j);
    e = cm_node_set_tag(n, "iq");
    if (e == CM_OK) e = cm_node_set_attr_str(n, "id", "12345");
    if (e == CM_OK) e = cm_node_set_attr_str(n, "xmlns", "usync");
    if (which >= 1 && e == CM_OK) e = cm_jid_set_ad(&j, "5551234567", CM_DOMAIN_WHATSAPP, 7);
    if (which >= 1 && e == CM_OK) e = cm_node_set_attr_jid(n, "to", &j);
    if (which >= 2 && e == CM_OK) {
        cm_node ch;

        cm_node_init(&ch);
        e = cm_node_set_tag(&ch, "query");
        if (e == CM_OK) e = cm_node_set_content_str(&ch, "hello world, this is some content");
        if (e == CM_OK) e = cm_node_add_child(n, &ch);
        else cm_node_free(&ch);
    }
    if (which >= 3 && e == CM_OK) {
        uint8_t blob[300];
        cm_node ch;

        fill_pat(blob, sizeof blob);
        cm_node_init(&ch);
        e = cm_node_set_tag(&ch, "enc");
        if (e == CM_OK) e = cm_node_set_content_bytes(&ch, blob, sizeof blob);
        if (e == CM_OK) e = cm_node_add_child(n, &ch);
        else cm_node_free(&ch);
    }
    cm_jid_free(&j);
    return e;
}

static void test_fuzz(void)
{
    uint32_t rng = 0x12345678u;
    int k, iters = 0;

    for (k = 0; k < 4; k++) {
        cm_node seed;
        uint8_t *un = NULL, *buf;
        size_t unlen = 0, i;

        CHECK_ERR(build_fuzz_seed(k, &seed), CM_OK);
        {
            uint8_t *m = NULL;
            size_t ml = 0;

            CHECK_ERR(cm_binary_marshal(&seed, &m, &ml), CM_OK);
            if (m == NULL || cm_binary_unpack(m, ml, &un, &unlen) != CM_OK)
                un = NULL;
            free(m);
        }
        cm_node_free(&seed);
        buf = (uint8_t *)malloc(unlen);
        if (buf == NULL || un == NULL) {
            free(buf);
            free(un);
            continue;
        }
        for (i = 0; i < 4000; i++) {
            cm_node n;
            int m, muts = 1 + (int)(rng % 4);

            memcpy(buf, un, unlen);
            for (m = 0; m < muts; m++) {
                rng = rng * 1664525u + 1013904223u;
                buf[(rng >> 8) % unlen] = (uint8_t)(rng >> 24);
            }
            cm_node_init(&n);
            if (cm_binary_unmarshal(buf, unlen, &n) == CM_OK) {
                uint8_t *re;
                size_t relen;

                /* whatever decoded must be re-encodable */
                if (cm_binary_marshal(&n, &re, &relen) == CM_OK)
                    free(re);
            }
            cm_node_free(&n);
            iters++;
        }
        free(buf);
        free(un);
    }
    printf("  fuzz: %d mutated inputs survived\n", iters);
}

int main(void)
{
    test_tokens();
    test_jid_manual();
    test_node_api();
    test_handcrafted();
    test_unpack();
    test_encoder_limits();
    test_fuzz();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

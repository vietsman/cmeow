/* See include/common.h for license and attribution.
 * Port of whatsmeow pair-code.go: link a device with an 8-character code typed on the phone. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "crypto.h"
#include "user.h"
#include "client_priv.h"

#define PBKDF2_ITER (2 << 16)
static const char B32[] = "123456789ABCDEFGHJKLMNPQRSTVWXYZ";

struct pair_state {
    cm_keypair eph;
    char code[9];
    uint8_t *ref;
    size_t reflen;
    char *phone_jid; /* "<digits>@s.whatsapp.net" */
};

void cmi_paircode_free(cm_client *c)
{
    struct pair_state *s = (struct pair_state *)c->mod_user;

    if (s == NULL)
        return;
    cm_cleanse(&s->eph, sizeof(s->eph));
    free(s->ref);
    free(s->phone_jid);
    free(s);
    c->mod_user = NULL;
}

/* AES-256-CTR, in place semantics allowed (same buffer). */
static int ctr_xor(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t n, uint8_t *out)
{
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int l = 0, ok = 0;

    if (x == NULL)
        return 0;
    if (EVP_EncryptInit_ex(x, EVP_aes_256_ctr(), NULL, key, iv) == 1 && EVP_EncryptUpdate(x, out, &l, in, (int)n) == 1 &&
        (size_t)l == n)
        ok = 1;
    EVP_CIPHER_CTX_free(x);
    return ok;
}

static int derive_code_key(const char *code, const uint8_t salt[32], uint8_t key[32])
{
    return PKCS5_PBKDF2_HMAC(code, (int)strlen(code), salt, 32, PBKDF2_ITER, EVP_sha256(), 32, key) == 1;
}

static const cm_node *find_child_tag(const cm_node *n, const char *tag)
{
    return n ? cm_node_child(n, tag) : NULL;
}

static cm_err bytes_child(cm_node *parent, const char *tag, const void *data, size_t len)
{
    cm_node ch;
    cm_err e = cmi_node(&ch, tag);

    if (e == CM_OK) e = cm_node_set_content_bytes(&ch, data, len);
    if (e == CM_OK) e = cm_node_add_child(parent, &ch);
    else cm_node_free(&ch);
    return e;
}

cm_err cm_client_pair_phone(cm_client *c, const char *phone, int show_push_notification, int client_type,
                            const char *display_name, char **code_out)
{
    struct pair_state *s;
    uint8_t salt[32], iv[16], rnd[5], key[32], wrapped[80];
    cm_node reg, *resp = NULL;
    const cm_node *ref;
    char digits[32];
    size_t i, nd = 0, rl = 0;
    const uint8_t *rb;
    cm_jid pj;
    cm_err e;
    uint64_t acc;

    if (c == NULL || phone == NULL || code_out == NULL)
        return CM_ERR_ARG;
    *code_out = NULL;
    if (c->dev->has_id)
        return CM_ERR_ARG; /* already paired */
    for (i = 0; phone[i]; i++)
        if (phone[i] >= '0' && phone[i] <= '9' && nd + 1 < sizeof digits)
            digits[nd++] = phone[i];
    digits[nd] = 0;
    if (nd < 7)
        return CM_ERR_ARG;
    if (client_type <= 0)
        client_type = 1;
    if (display_name == NULL)
        display_name = "Chrome (Linux)";

    cmi_paircode_free(c);
    s = (struct pair_state *)calloc(1, sizeof(*s));
    if (s == NULL)
        return CM_ERR_NOMEM;
    c->mod_user = s;
    if ((e = cm_keypair_generate(&s->eph)) != CM_OK || (e = cm_random(salt, 32)) != CM_OK ||
        (e = cm_random(iv, 16)) != CM_OK || (e = cm_random(rnd, 5)) != CM_OK)
        goto fail;
    /* 5 random bytes -> 8 characters, 5 bits each */
    acc = 0;
    for (i = 0; i < 5; i++)
        acc = (acc << 8) | rnd[i];
    for (i = 0; i < 8; i++)
        s->code[i] = B32[(acc >> (35 - 5 * i)) & 31];
    s->code[8] = 0;
    if (!derive_code_key(s->code, salt, key)) {
        e = CM_ERR_CRYPTO;
        goto fail;
    }
    memcpy(wrapped, salt, 32);
    memcpy(wrapped + 32, iv, 16);
    if (!ctr_xor(key, iv, s->eph.pub, 32, wrapped + 48)) {
        e = CM_ERR_CRYPTO;
        goto fail;
    }
    s->phone_jid = (char *)malloc(nd + 32);
    if (s->phone_jid == NULL) {
        e = CM_ERR_NOMEM;
        goto fail;
    }
    sprintf(s->phone_jid, "%s@%s", digits, CM_SERVER_DEFAULT_USER);

    cm_jid_init(&pj);
    cm_jid_set(&pj, digits, CM_SERVER_DEFAULT_USER);
    e = cmi_node(&reg, "link_code_companion_reg");
    if (e == CM_OK) e = cm_node_set_attr_jid(&reg, "jid", &pj);
    if (e == CM_OK) e = cm_node_set_attr_str(&reg, "stage", "companion_hello");
    if (e == CM_OK) e = cm_node_set_attr_str(&reg, "should_show_push_notification", show_push_notification ? "true" : "false");
    cm_jid_free(&pj);
    if (e == CM_OK) e = bytes_child(&reg, "link_code_pairing_wrapped_companion_ephemeral_pub", wrapped, sizeof wrapped);
    if (e == CM_OK) e = bytes_child(&reg, "companion_server_auth_key_pub", c->dev->noise_key.pub, 32);
    if (e == CM_OK) {
        char pt[16];
        cm_node ch;

        sprintf(pt, "%d", client_type);
        cmi_node(&ch, "companion_platform_id");
        cm_node_set_content_str(&ch, pt);
        e = cm_node_add_child(&reg, &ch);
    }
    if (e == CM_OK) {
        cm_node ch;

        cmi_node(&ch, "companion_platform_display");
        cm_node_set_content_str(&ch, display_name);
        e = cm_node_add_child(&reg, &ch);
    }
    if (e == CM_OK) {
        uint8_t zero = 0;

        e = bytes_child(&reg, "link_code_pairing_nonce", &zero, 1);
    }
    if (e != CM_OK) {
        cm_node_free(&reg);
        goto fail;
    }
    e = cm_client_iq(c, "md", "set", "", &reg, 0, &resp);
    cm_node_free(&reg);
    if (e != CM_OK)
        goto fail_resp;
    ref = find_child_tag(find_child_tag(resp, "link_code_companion_reg"), "link_code_pairing_ref");
    rb = ref ? cmi_bytes(ref, &rl) : NULL;
    if (rb == NULL || rl == 0) {
        e = CM_ERR_PROTO;
        goto fail_resp;
    }
    s->ref = (uint8_t *)cm_memdup(rb, rl);
    s->reflen = rl;
    cm_node_free(resp);
    free(resp);
    if (s->ref == NULL) {
        e = CM_ERR_NOMEM;
        goto fail;
    }
    {
        char *o = (char *)malloc(10);

        if (o == NULL) {
            e = CM_ERR_NOMEM;
            goto fail;
        }
        memcpy(o, s->code, 4);
        o[4] = '-';
        memcpy(o + 5, s->code + 4, 5);
        *code_out = o;
    }
    cm_cleanse(key, sizeof key);
    return CM_OK;
fail_resp:
    if (resp) {
        cm_node_free(resp);
        free(resp);
    }
fail:
    cm_cleanse(key, sizeof key);
    cmi_paircode_free(c);
    return e;
}

/* notification type=link_code_companion_reg, stage primary_hello */
void cmi_paircode_notification(cm_client *c, const cm_node *n)
{
    struct pair_state *s = (struct pair_state *)c->mod_user;
    const cm_node *lc = cm_node_child(n, "link_code_companion_reg"), *x;
    const uint8_t *ref, *wp, *pid;
    size_t rl = 0, wl = 0, pl = 0;
    uint8_t key[32], prim_eph[32], shared[32], id_shared[32], rnd[32], ksalt[32], nonce[12], exp[32];
    uint8_t plain[96], bundle[32 + 12 + 96 + 16], adv_in[96], adv[32];
    cm_node fin, *resp = NULL;
    const char *stage;
    cm_jid pj;

    if (s == NULL || s->ref == NULL || lc == NULL)
        return;
    stage = cmi_attr(lc, "stage");
    if (stage == NULL || strcmp(stage, "primary_hello") != 0)
        return;
    x = cm_node_child(lc, "link_code_pairing_ref");
    ref = x ? cmi_bytes(x, &rl) : NULL;
    if (ref == NULL || rl != s->reflen || memcmp(ref, s->ref, rl) != 0)
        return;
    x = cm_node_child(lc, "link_code_pairing_wrapped_primary_ephemeral_pub");
    wp = x ? cmi_bytes(x, &wl) : NULL;
    x = cm_node_child(lc, "primary_identity_pub");
    pid = x ? cmi_bytes(x, &pl) : NULL;
    if (wp == NULL || wl != 80 || pid == NULL || pl != 32)
        return;
    if (!derive_code_key(s->code, wp, key) || !ctr_xor(key, wp + 32, wp + 48, 32, prim_eph))
        return;
    if (cm_x25519(s->eph.priv, prim_eph, shared) != CM_OK)
        return;
    if (cm_random(rnd, 32) != CM_OK || cm_random(ksalt, 32) != CM_OK || cm_random(nonce, 12) != CM_OK)
        return;
    if (cm_hkdf_sha256(shared, 32, ksalt, 32, "link_code_pairing_key_bundle_encryption_key",
                       strlen("link_code_pairing_key_bundle_encryption_key"), exp, 32) != CM_OK)
        return;
    memcpy(plain, c->dev->identity_key.pub, 32);
    memcpy(plain + 32, pid, 32);
    memcpy(plain + 64, rnd, 32);
    memcpy(bundle, ksalt, 32);
    memcpy(bundle + 32, nonce, 12);
    if (cm_aes256gcm_seal(exp, nonce, NULL, 0, plain, 96, bundle + 44) != CM_OK)
        return;
    if (cm_x25519(c->dev->identity_key.priv, pid, id_shared) != CM_OK)
        return;
    memcpy(adv_in, shared, 32);
    memcpy(adv_in + 32, id_shared, 32);
    memcpy(adv_in + 64, rnd, 32);
    if (cm_hkdf_sha256(adv_in, 96, NULL, 0, "adv_secret", strlen("adv_secret"), adv, 32) != CM_OK)
        return;
    memcpy(c->dev->adv_secret_key, adv, 32);

    cm_jid_init(&pj);
    if (cm_jid_parse(&pj, s->phone_jid) != CM_OK)
        return;
    cmi_node(&fin, "link_code_companion_reg");
    cm_node_set_attr_jid(&fin, "jid", &pj);
    cm_node_set_attr_str(&fin, "stage", "companion_finish");
    cm_jid_free(&pj);
    bytes_child(&fin, "link_code_pairing_wrapped_key_bundle", bundle, sizeof bundle);
    bytes_child(&fin, "companion_identity_public", c->dev->identity_key.pub, 32);
    bytes_child(&fin, "link_code_pairing_ref", s->ref, s->reflen);
    cm_client_iq(c, "md", "set", "", &fin, 0, &resp);
    cm_node_free(&fin);
    if (resp) {
        cm_node_free(resp);
        free(resp);
    }
    cm_cleanse(key, sizeof key);
    cm_cleanse(shared, sizeof shared);
    cm_cleanse(id_shared, sizeof id_shared);
    cm_cleanse(adv, sizeof adv);
    cm_cleanse(adv_in, sizeof adv_in);
    cm_cleanse(plain, sizeof plain);
}

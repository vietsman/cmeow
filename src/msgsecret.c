/* See include/common.h for license and attribution. Port of whatsmeow msgsecret.go. */
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "msgsecret.h"

static cm_err derive(const char *use_case, const cm_jid *msender, const char *orig_id, const cm_jid *osender,
                     const uint8_t secret[32], uint8_t key[32], char **ad, size_t *adlen)
{
    cm_jid a, b;
    char *os = NULL, *ms = NULL, *info = NULL;
    size_t il;
    cm_err e;

    *ad = NULL;
    *adlen = 0;
    cm_jid_init(&a);
    cm_jid_init(&b);
    if ((e = cm_jid_to_non_ad(&a, osender)) != CM_OK || (e = cm_jid_to_non_ad(&b, msender)) != CM_OK ||
        (e = cm_jid_to_string(&a, &os)) != CM_OK || (e = cm_jid_to_string(&b, &ms)) != CM_OK)
        goto out;
    il = strlen(orig_id) + strlen(os) + strlen(ms) + strlen(use_case);
    info = (char *)malloc(il + 1);
    if (info == NULL) {
        e = CM_ERR_NOMEM;
        goto out;
    }
    strcpy(info, orig_id);
    strcat(info, os);
    strcat(info, ms);
    strcat(info, use_case);
    if ((e = cm_hkdf_sha256(secret, 32, NULL, 0, info, il, key, 32)) != CM_OK)
        goto out;
    if (strcmp(use_case, CM_SECRET_POLL_VOTE) == 0 || strcmp(use_case, CM_SECRET_EVENT_RESPONSE) == 0) {
        size_t n1 = strlen(orig_id), n2 = strlen(ms);

        *ad = (char *)malloc(n1 + 1 + n2 + 1);
        if (*ad == NULL) {
            e = CM_ERR_NOMEM;
            goto out;
        }
        memcpy(*ad, orig_id, n1);
        (*ad)[n1] = 0;
        memcpy(*ad + n1 + 1, ms, n2);
        *adlen = n1 + 1 + n2;
    }
out:
    free(os);
    free(ms);
    free(info);
    cm_jid_free(&a);
    cm_jid_free(&b);
    return e;
}

cm_err cm_msgsecret_decrypt(const char *use_case, const cm_jid *modification_sender, const char *orig_id,
                            const cm_jid *orig_sender, const uint8_t secret[32],
                            const uint8_t *iv, size_t iv_len, const uint8_t *payload, size_t payload_len,
                            uint8_t **out, size_t *out_len)
{
    uint8_t key[32];
    char *ad;
    size_t adl;
    uint8_t *pt;
    cm_err e;

    if (!use_case || !modification_sender || !orig_id || !orig_sender || !secret || !iv || !payload || !out ||
        !out_len || iv_len != 12 || payload_len < 16)
        return CM_ERR_ARG;
    *out = NULL;
    if ((e = derive(use_case, modification_sender, orig_id, orig_sender, secret, key, &ad, &adl)) != CM_OK)
        return e;
    pt = (uint8_t *)malloc(payload_len - 16 + 1);
    if (pt == NULL) {
        free(ad);
        return CM_ERR_NOMEM;
    }
    e = cm_aes256gcm_open(key, iv, ad, adl, payload, payload_len, pt);
    cm_cleanse(key, sizeof key);
    free(ad);
    if (e != CM_OK) {
        free(pt);
        return e;
    }
    *out = pt;
    *out_len = payload_len - 16;
    return CM_OK;
}

cm_err cm_msgsecret_encrypt(const char *use_case, const cm_jid *modification_sender, const char *orig_id,
                            const cm_jid *orig_sender, const uint8_t secret[32],
                            const uint8_t *plain, size_t plain_len,
                            uint8_t iv[12], uint8_t **payload, size_t *payload_len)
{
    uint8_t key[32];
    char *ad;
    size_t adl;
    uint8_t *ct;
    cm_err e;

    if (!use_case || !modification_sender || !orig_id || !orig_sender || !secret || !plain || !iv || !payload ||
        !payload_len)
        return CM_ERR_ARG;
    *payload = NULL;
    if ((e = derive(use_case, modification_sender, orig_id, orig_sender, secret, key, &ad, &adl)) != CM_OK)
        return e;
    ct = (uint8_t *)malloc(plain_len + 16);
    if (ct == NULL || (e = cm_random(iv, 12)) != CM_OK) {
        free(ct);
        free(ad);
        return e != CM_OK ? e : CM_ERR_NOMEM;
    }
    e = cm_aes256gcm_seal(key, iv, ad, adl, plain, plain_len, ct);
    cm_cleanse(key, sizeof key);
    free(ad);
    if (e != CM_OK) {
        free(ct);
        return e;
    }
    *payload = ct;
    *payload_len = plain_len + 16;
    return CM_OK;
}

cm_err cm_poll_option_hash(const char *name, uint8_t out[32])
{
    return cm_sha256(name, strlen(name), out);
}

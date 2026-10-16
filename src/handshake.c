/* See include/common.h for license and attribution. Port of whatsmeow/handshake.go. */
#include "handshake.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "waCert/WACert.pb-c.h"
#include "waWa6/WAWebProtobufsWa6.pb-c.h"

/* libsignal-protocol-c's curve25519 signatures (curve25519/ed25519/additions/curve_sigs.h) */
extern int curve25519_sign(unsigned char *signature_out, const unsigned char *curve25519_privkey,
                           const unsigned char *msg, const unsigned long msg_len,
                           const unsigned char *random);
extern int curve25519_verify(const unsigned char *signature, const unsigned char *curve25519_pubkey,
                             const unsigned char *msg, const unsigned long msg_len);

const uint8_t cm_wa_cert_pubkey[32] = {
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
    0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b};

cm_err cm_xeddsa_sign(const uint8_t priv[32], const void *msg, size_t len, uint8_t sig[64])
{
    uint8_t rnd[64];
    cm_err e = cm_random(rnd, sizeof(rnd));

    if (e != CM_OK)
        return e;
    if (curve25519_sign(sig, priv, (const unsigned char *)msg, (unsigned long)len, rnd) != 0)
        e = CM_ERR_CRYPTO;
    cm_cleanse(rnd, sizeof(rnd));
    return e;
}

cm_err cm_xeddsa_verify(const uint8_t pub[32], const void *msg, size_t len, const uint8_t sig[64])
{
    return curve25519_verify(sig, pub, (const unsigned char *)msg, (unsigned long)len) == 0
               ? CM_OK
               : CM_ERR_AUTH;
}

static void set_err(cm_hs_error *err, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL)
        return;
    va_start(ap, fmt);
    vsnprintf(err->message, sizeof(err->message), fmt, ap);
    va_end(ap);
}

/* ---- certificate chain ---- */

/* checkCertValidity */
static cm_err check_cert_validity(const WACert__CertChain__NoiseCertificate__Details *d,
                                  int64_t now, const char *who, cm_hs_error *err)
{
    /* Go converts uint32-sized unix timestamps; the proto field is uint64 */
    if (now < (int64_t)d->notbefore) {
        set_err(err, "%s certificate not valid yet (current time %lld is before %llu)", who,
                (long long)now, (unsigned long long)d->notbefore);
        return CM_ERR_AUTH;
    }
    if (now > (int64_t)d->notafter) {
        set_err(err, "%s certificate expired (current time %lld is after %llu)", who,
                (long long)now, (unsigned long long)d->notafter);
        return CM_ERR_AUTH;
    }
    return CM_OK;
}

cm_err cm_verify_server_cert(const uint8_t *cert, size_t cert_len,
                             const uint8_t static_key[32], int64_t now,
                             const uint8_t *root_pub, cm_hs_error *err)
{
    WACert__CertChain *chain;
    WACert__CertChain__NoiseCertificate__Details *inter = NULL, *leaf = NULL;
    const WACert__CertChain__NoiseCertificate *ic, *lc;
    cm_err e = CM_ERR_AUTH;

    if (root_pub == NULL)
        root_pub = cm_wa_cert_pubkey;
    chain = wacert__cert_chain__unpack(NULL, cert_len, cert);
    if (chain == NULL) {
        set_err(err, "failed to unmarshal noise certificate");
        return CM_ERR_PROTO;
    }
    ic = chain->intermediate;
    lc = chain->leaf;
    if (ic == NULL || lc == NULL || !ic->has_details || !ic->has_signature ||
        !lc->has_details || !lc->has_signature) {
        set_err(err, "missing parts of noise certificate");
        e = CM_ERR_PROTO;
        goto done;
    }
    if (ic->signature.len != 64) {
        set_err(err, "unexpected length of intermediate cert signature %lu (expected 64)",
                (unsigned long)ic->signature.len);
        goto done;
    }
    if (lc->signature.len != 64) {
        set_err(err, "unexpected length of leaf cert signature %lu (expected 64)",
                (unsigned long)lc->signature.len);
        goto done;
    }
    if (cm_xeddsa_verify(root_pub, ic->details.data, ic->details.len, ic->signature.data) != CM_OK) {
        set_err(err, "failed to verify intermediate cert signature");
        goto done;
    }
    inter = (WACert__CertChain__NoiseCertificate__Details *)protobuf_c_message_unpack(
        &wacert__cert_chain__noise_certificate__details__descriptor, NULL, ic->details.len,
        ic->details.data);
    if (inter == NULL) {
        set_err(err, "failed to unmarshal noise certificate details");
        e = CM_ERR_PROTO;
        goto done;
    }
    if (inter->issuerserial != CM_WA_CERT_ISSUER_SERIAL) {
        set_err(err, "unexpected intermediate issuer serial %lu (expected %d)",
                (unsigned long)inter->issuerserial, CM_WA_CERT_ISSUER_SERIAL);
        goto done;
    }
    if (inter->key.len != 32) {
        set_err(err, "unexpected length of intermediate cert key %lu (expected 32)",
                (unsigned long)inter->key.len);
        goto done;
    }
    if (cm_xeddsa_verify(inter->key.data, lc->details.data, lc->details.len, lc->signature.data) != CM_OK) {
        /* whatsmeow reuses the "intermediate" wording for this failure; keep it */
        set_err(err, "failed to verify intermediate cert signature");
        goto done;
    }
    if (check_cert_validity(inter, now, "intermediate cert", err) != CM_OK)
        goto done;
    leaf = (WACert__CertChain__NoiseCertificate__Details *)protobuf_c_message_unpack(
        &wacert__cert_chain__noise_certificate__details__descriptor, NULL, lc->details.len,
        lc->details.data);
    if (leaf == NULL) {
        set_err(err, "failed to unmarshal noise certificate details");
        e = CM_ERR_PROTO;
        goto done;
    }
    if (leaf->issuerserial != inter->serial) {
        set_err(err, "unexpected leaf issuer serial %lu (expected %lu)",
                (unsigned long)leaf->issuerserial, (unsigned long)inter->serial);
        goto done;
    }
    if (leaf->key.len != 32 || !cm_ct_equal(leaf->key.data, static_key, 32)) {
        set_err(err, "cert key doesn't match decrypted static");
        goto done;
    }
    if (check_cert_validity(leaf, now, "leaf cert cert", err) != CM_OK)
        goto done;
    e = CM_OK;
done:
    if (inter)
        protobuf_c_message_free_unpacked(&inter->base, NULL);
    if (leaf)
        protobuf_c_message_free_unpacked(&leaf->base, NULL);
    wacert__cert_chain__free_unpacked(chain, NULL);
    return e;
}

/* ---- handshake ---- */

cm_err cm_handshake_begin(cm_handshake *hs, const cm_keypair *ephemeral,
                          uint8_t **out, size_t *out_len)
{
    WAWebProtobufsWa6__HandshakeMessage msg = WAWEB_PROTOBUFS_WA6__HANDSHAKE_MESSAGE__INIT;
    WAWebProtobufsWa6__HandshakeMessage__ClientHello hello =
        WAWEB_PROTOBUFS_WA6__HANDSHAKE_MESSAGE__CLIENT_HELLO__INIT;
    size_t n;
    uint8_t *buf;
    cm_err e;

    memset(hs, 0, sizeof(*hs));
    hs->ephemeral = *ephemeral;
    cm_conn_header(hs->header);
    e = cm_noise_start(&hs->nh, CM_NOISE_START_PATTERN, CM_NOISE_START_PATTERN_LEN,
                       hs->header, CM_CONN_HEADER_LEN);
    if (e == CM_OK)
        e = cm_noise_authenticate(&hs->nh, hs->ephemeral.pub, 32);
    if (e != CM_OK)
        return e;

    hello.has_ephemeral = 1;
    hello.ephemeral.data = hs->ephemeral.pub;
    hello.ephemeral.len = 32;
    msg.clienthello = &hello;
    n = waweb_protobufs_wa6__handshake_message__get_packed_size(&msg);
    buf = (uint8_t *)malloc(n ? n : 1);
    if (buf == NULL)
        return CM_ERR_NOMEM;
    waweb_protobufs_wa6__handshake_message__pack(&msg, buf);
    *out = buf;
    *out_len = n;
    return CM_OK;
}

cm_err cm_handshake_finish(cm_handshake *hs, const uint8_t *server_hello, size_t hello_len,
                           const cm_keypair *noise_key,
                           const uint8_t *client_payload, size_t payload_len,
                           int64_t now_unix, const uint8_t *root_pub,
                           uint8_t **out, size_t *out_len,
                           cm_noise_transport *transport, cm_hs_error *err)
{
    WAWebProtobufsWa6__HandshakeMessage *resp;
    const WAWebProtobufsWa6__HandshakeMessage__ServerHello *sh;
    uint8_t server_eph[32], static_dec[32], enc_pub[32 + CM_GCM_TAG_LEN];
    uint8_t *cert_dec = NULL, *enc_payload = NULL, *packed = NULL;
    cm_err e;
    size_t cert_len;

    resp = waweb_protobufs_wa6__handshake_message__unpack(NULL, hello_len, server_hello);
    if (resp == NULL) {
        set_err(err, "failed to unmarshal handshake response");
        return CM_ERR_PROTO;
    }
    sh = resp->serverhello;
    if (sh == NULL || !sh->has_ephemeral || sh->ephemeral.len != 32 || !sh->has_static_ ||
        !sh->has_payload) {
        set_err(err, "missing parts of handshake response");
        e = CM_ERR_PROTO;
        goto done;
    }
    memcpy(server_eph, sh->ephemeral.data, 32);

    e = cm_noise_authenticate(&hs->nh, server_eph, 32);
    if (e == CM_OK)
        e = cm_noise_mix_shared_secret(&hs->nh, hs->ephemeral.priv, server_eph);
    if (e != CM_OK) {
        set_err(err, "failed to mix server ephemeral key in: %s", cm_strerror(e));
        goto done;
    }

    if (sh->static_.len != 32 + CM_GCM_TAG_LEN) {
        /* Go decrypts anything and then checks the plaintext length is 32 */
        set_err(err, "unexpected length of server static plaintext %ld (expected 32)",
                (long)sh->static_.len - CM_GCM_TAG_LEN);
        e = sh->static_.len < CM_GCM_TAG_LEN ? CM_ERR_AUTH : CM_ERR_PROTO;
        /* still must authenticate to be faithful about *which* error wins */
        if (sh->static_.len >= CM_GCM_TAG_LEN) {
            uint8_t *tmp = (uint8_t *)malloc(sh->static_.len);
            if (tmp == NULL) {
                e = CM_ERR_NOMEM;
                goto done;
            }
            if (cm_noise_decrypt(&hs->nh, sh->static_.data, sh->static_.len, tmp) != CM_OK) {
                set_err(err, "failed to decrypt server static ciphertext");
                e = CM_ERR_AUTH;
            }
            free(tmp);
        } else {
            set_err(err, "failed to decrypt server static ciphertext");
        }
        goto done;
    }
    e = cm_noise_decrypt(&hs->nh, sh->static_.data, sh->static_.len, static_dec);
    if (e != CM_OK) {
        set_err(err, "failed to decrypt server static ciphertext");
        goto done;
    }
    e = cm_noise_mix_shared_secret(&hs->nh, hs->ephemeral.priv, static_dec);
    if (e != CM_OK) {
        set_err(err, "failed to mix server static key in: %s", cm_strerror(e));
        goto done;
    }

    if (sh->payload.len < CM_GCM_TAG_LEN) {
        set_err(err, "failed to decrypt noise certificate ciphertext");
        e = CM_ERR_AUTH;
        goto done;
    }
    cert_len = sh->payload.len - CM_GCM_TAG_LEN;
    cert_dec = (uint8_t *)malloc(cert_len ? cert_len : 1);
    if (cert_dec == NULL) {
        e = CM_ERR_NOMEM;
        goto done;
    }
    e = cm_noise_decrypt(&hs->nh, sh->payload.data, sh->payload.len, cert_dec);
    if (e != CM_OK) {
        set_err(err, "failed to decrypt noise certificate ciphertext");
        goto done;
    }
    e = cm_verify_server_cert(cert_dec, cert_len, static_dec, now_unix, root_pub, err);
    if (e != CM_OK)
        goto done;

    e = cm_noise_encrypt(&hs->nh, noise_key->pub, 32, enc_pub);
    if (e == CM_OK)
        e = cm_noise_mix_shared_secret(&hs->nh, noise_key->priv, server_eph);
    if (e != CM_OK) {
        set_err(err, "failed to mix noise private key in: %s", cm_strerror(e));
        goto done;
    }

    enc_payload = (uint8_t *)malloc(payload_len + CM_GCM_TAG_LEN);
    if (enc_payload == NULL) {
        e = CM_ERR_NOMEM;
        goto done;
    }
    e = cm_noise_encrypt(&hs->nh, client_payload, payload_len, enc_payload);
    if (e != CM_OK)
        goto done;
    {
        WAWebProtobufsWa6__HandshakeMessage msg = WAWEB_PROTOBUFS_WA6__HANDSHAKE_MESSAGE__INIT;
        WAWebProtobufsWa6__HandshakeMessage__ClientFinish fin =
            WAWEB_PROTOBUFS_WA6__HANDSHAKE_MESSAGE__CLIENT_FINISH__INIT;
        size_t n;

        fin.has_static_ = 1;
        fin.static_.data = enc_pub;
        fin.static_.len = sizeof(enc_pub);
        fin.has_payload = 1;
        fin.payload.data = enc_payload;
        fin.payload.len = payload_len + CM_GCM_TAG_LEN;
        msg.clientfinish = &fin;
        n = waweb_protobufs_wa6__handshake_message__get_packed_size(&msg);
        packed = (uint8_t *)malloc(n ? n : 1);
        if (packed == NULL) {
            e = CM_ERR_NOMEM;
            goto done;
        }
        waweb_protobufs_wa6__handshake_message__pack(&msg, packed);
        *out_len = n;
    }
    e = cm_noise_finish(&hs->nh, transport);
    if (e != CM_OK) {
        set_err(err, "failed to extract final keys: %s", cm_strerror(e));
        goto done;
    }
    *out = packed;
    packed = NULL;
done:
    free(packed);
    free(enc_payload);
    free(cert_dec);
    waweb_protobufs_wa6__handshake_message__free_unpacked(resp, NULL);
    return e;
}

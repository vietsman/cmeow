/* See include/common.h for license and attribution.
 * Port of whatsmeow download.go, download-to-file.go, upload.go, mediaconn.go, mediaretry.go.
 *
 * Transfers are blocking and run on the caller's thread (the websocket is not serviced meanwhile,
 * so very long transfers may trigger a keepalive timeout; call from a quiet moment). */
#ifndef CMEOW_MEDIA_H
#define CMEOW_MEDIA_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { CM_EXT_MEDIA_RETRY = 400 }; /* cm_media_retry_evt */

typedef enum cm_media_type {
    CM_MEDIA_IMAGE,
    CM_MEDIA_VIDEO,
    CM_MEDIA_AUDIO,
    CM_MEDIA_DOCUMENT,
    CM_MEDIA_HISTORY,
    CM_MEDIA_APPSTATE,
    CM_MEDIA_STICKER_PACK,
    CM_MEDIA_LINK_THUMBNAIL
} cm_media_type;

const char *cm_media_app_info(cm_media_type t); /* e.g. "WhatsApp Image Keys" */
const char *cm_media_mms_type(cm_media_type t); /* e.g. "image" */

/* ---- key schedule and one-shot crypto (also usable without a client) ---- */
typedef struct cm_media_keys {
    uint8_t iv[16], cipher_key[32], mac_key[32], ref_key[32];
} cm_media_keys;
cm_err cm_media_keys_derive(const uint8_t *media_key, size_t len, cm_media_type t, cm_media_keys *out);
/* plain -> AES-256-CBC(PKCS7) || first 10 bytes of HMAC-SHA256(iv||ciphertext) */
cm_err cm_media_encrypt(const cm_media_keys *k, const uint8_t *plain, size_t n, uint8_t **out, size_t *olen);
/* inverse; CM_ERR_AUTH on a MAC mismatch */
cm_err cm_media_decrypt(const cm_media_keys *k, const uint8_t *data, size_t n, uint8_t **plain, size_t *olen);

/* ---- download ---- */
typedef struct cm_download_info {
    const char *direct_path;     /* "/v/t62...?..." (preferred) */
    const char *url;             /* full URL, used when direct_path is empty */
    const uint8_t *media_key;    /* NULL (with enc_sha256 NULL) = unencrypted */
    size_t media_key_len;
    const uint8_t *enc_sha256;   /* 32 bytes or NULL */
    const uint8_t *file_sha256;  /* 32 bytes or NULL (skip plaintext hash check) */
    cm_media_type type;
    int http_status;             /* out: last HTTP status (403/404/410 mean "ask the phone to re-upload") */
} cm_download_info;

cm_err cm_client_download(cm_client *c, cm_download_info *info, uint8_t **out, size_t *len);
cm_err cm_client_download_to_file(cm_client *c, cm_download_info *info, const char *path);
/* DownloadAny: finds the media inside a serialized waE2E.Message (image/video/audio/document/sticker). */
cm_err cm_client_download_message(cm_client *c, const uint8_t *msg, size_t len, uint8_t **out, size_t *olen);

/* ---- upload ---- */
typedef struct cm_upload_resp {
    char *url, *direct_path, *handle, *object_id; /* malloc()ed */
    uint8_t media_key[32], file_enc_sha256[32], file_sha256[32];
    int has_keys;                                 /* 0 for newsletter uploads */
    uint64_t file_length;
} cm_upload_resp;
void cm_upload_resp_free(cm_upload_resp *r);

typedef long (*cm_media_read_cb)(void *ud, uint8_t *buf, size_t n); /* 0 = EOF, <0 = error */
cm_err cm_client_upload(cm_client *c, const uint8_t *data, size_t len, cm_media_type t, cm_upload_resp *out);
cm_err cm_client_upload_stream(cm_client *c, cm_media_read_cb rd, void *ud, cm_media_type t, cm_upload_resp *out);
cm_err cm_client_upload_file(cm_client *c, const char *path, cm_media_type t, cm_upload_resp *out);
cm_err cm_client_upload_newsletter(cm_client *c, const uint8_t *data, size_t len, cm_media_type t,
                                   cm_upload_resp *out);
cm_err cm_client_delete_media(cm_client *c, cm_media_type t, const char *direct_path,
                              const uint8_t *enc_sha256, const char *handle);

/* Builds a serialized waE2E.Message for an uploaded file (caption/filename/mimetype optional). */
uint8_t *cm_message_build_media(cm_media_type t, const cm_upload_resp *u, const char *mimetype, const char *caption,
                                const char *filename, int voice_note, size_t *len);

/* ---- media retry (ask the phone to re-upload expired media) ---- */
cm_err cm_client_send_media_retry(cm_client *c, const cm_jid *chat, const cm_jid *sender, int is_group,
                                  int from_me, const char *msg_id, const uint8_t *media_key, size_t key_len);

typedef struct cm_media_retry_evt {
    const char *msg_id;
    const cm_jid *chat, *sender;
    int from_me;
    int64_t timestamp;
    int error_code;                 /* >0 when the server reported an error (no ciphertext) */
    const uint8_t *ciphertext;      /* enc_p */
    size_t ciphertext_len;
    const uint8_t *iv;              /* enc_iv */
    size_t iv_len;
} cm_media_retry_evt;

typedef struct cm_media_retry_result {
    int result;                     /* 1 success, 2 not found on phone, 3 decryption error, 0 general error */
    char *direct_path;              /* malloc()ed; NULL unless success */
} cm_media_retry_result;
cm_err cm_media_retry_decrypt(const cm_media_retry_evt *evt, const uint8_t *media_key, size_t key_len,
                              cm_media_retry_result *out);

#ifdef __cplusplus
}
#endif
#endif

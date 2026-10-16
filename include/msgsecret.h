/* See include/common.h for license and attribution.
 * Port of whatsmeow msgsecret.go: polls, event responses and encrypted reactions/comments are
 * AES-GCM encrypted with a key derived from the original message's messageSecret
 * (MessageContextInfo.messageSecret, 32 bytes). The caller supplies that secret; cmeow keeps no
 * message store. */
#ifndef CMEOW_MSGSECRET_H
#define CMEOW_MSGSECRET_H

#include "common.h"
#include "jid.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_SECRET_POLL_VOTE      "Poll Vote"
#define CM_SECRET_EVENT_RESPONSE "Event Response"
#define CM_SECRET_REACTION       "Enc Reaction"
#define CM_SECRET_COMMENT        "Enc Comment"

/* Decrypts a payload (encPayload || 16-byte tag, iv 12 bytes) produced by `modification_sender` for
 * the original message (id + sender). *out is malloc()ed. CM_ERR_AUTH on a wrong secret/ids. */
cm_err cm_msgsecret_decrypt(const char *use_case, const cm_jid *modification_sender, const char *orig_id,
                            const cm_jid *orig_sender, const uint8_t secret[32],
                            const uint8_t *iv, size_t iv_len, const uint8_t *payload, size_t payload_len,
                            uint8_t **out, size_t *out_len);

/* Encrypts plaintext with a random 12-byte iv. *payload is malloc()ed (ciphertext||tag). */
cm_err cm_msgsecret_encrypt(const char *use_case, const cm_jid *modification_sender, const char *orig_id,
                            const cm_jid *orig_sender, const uint8_t secret[32],
                            const uint8_t *plain, size_t plain_len,
                            uint8_t iv[12], uint8_t **payload, size_t *payload_len);

/* Poll option identifier: sha256(option name). */
cm_err cm_poll_option_hash(const char *name, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
#endif

/* Internal to the appstate module. */
#ifndef CMEOW_APPSTATE_PRIV_H
#define CMEOW_APPSTATE_PRIV_H

#include "client_priv.h"
#include "appstate.h"
#include "waServerSync/WAWebProtobufsServerSync.pb-c.h"
#include "waSyncAction/WAWebProtobufSyncAction.pb-c.h"

typedef WAWebProtobufsServerSync__SyncdPatch SPatch;
typedef WAWebProtobufsServerSync__SyncdSnapshot SSnap;
typedef WAWebProtobufsServerSync__SyncdMutation SMut;
typedef WAWebProtobufSyncAction__SyncActionData SAData;
typedef WAWebProtobufSyncAction__SyncActionValue SAValue;

#define AS_ERR_NOKEY ((cm_err)1000) /* app state key missing */

typedef struct as_keys {
    uint8_t index[32], value_enc[32], value_mac[32], snapshot_mac[32], patch_mac[32];
} as_keys;

cm_err as_expand_keys(const uint8_t *key_data, size_t len, as_keys *out);

/* lthash + MACs */
void as_lthash_apply(uint8_t hash[128], const uint8_t *item, size_t len, int subtract);
cm_err as_snapshot_mac(const uint8_t hash[128], uint64_t version, const char *name, const uint8_t key[32],
                       uint8_t out[32]);
cm_err as_patch_mac(const SPatch *p, const char *name, const uint8_t key[32], uint64_t version, uint8_t out[32]);
cm_err as_content_mac(int op, const uint8_t *data, size_t len, const uint8_t *key_id, size_t kid_len,
                      const uint8_t key[32], uint8_t out[32]);
cm_err as_index_mac(const uint8_t key[32], const uint8_t *index_json, size_t len, uint8_t out[32]);

/* value (de)cryption: blob = iv(16) || ciphertext (CBC, PKCS7) */
cm_err as_decrypt_value(const uint8_t key[32], const uint8_t *blob, size_t len, uint8_t **out, size_t *olen);
cm_err as_encrypt_value(const uint8_t key[32], const uint8_t *plain, size_t len, uint8_t **out, size_t *olen);

#endif

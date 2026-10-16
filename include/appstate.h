/* See include/common.h for license and attribution.
 * Port of whatsmeow appstate/ and appstate.go. App state ("syncd") is the encrypted, MAC-chained
 * settings/contacts/chat-flags database that the phone shares with linked devices. */
#ifndef CMEOW_APPSTATE_H
#define CMEOW_APPSTATE_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CM_EXT_APPSTATE_MUTATION = 200,  /* cm_appstate_mutation */
    CM_EXT_APPSTATE_SYNC_DONE,       /* cm_appstate_sync_evt (full sync or recovery completed) */
    CM_EXT_APPSTATE_SYNC_ERROR       /* cm_appstate_sync_evt (err set) */
};

#define CM_AS_CRITICAL_BLOCK "critical_block"
#define CM_AS_CRITICAL_UNBLOCK_LOW "critical_unblock_low"
#define CM_AS_REGULAR_HIGH "regular_high"
#define CM_AS_REGULAR "regular"
#define CM_AS_REGULAR_LOW "regular_low"

/* Known index[0] values (see whatsmeow appstate.Index*): */
#define CM_AS_IDX_MUTE "mute"
#define CM_AS_IDX_PIN "pin_v1"
#define CM_AS_IDX_ARCHIVE "archive"
#define CM_AS_IDX_STAR "star"
#define CM_AS_IDX_CONTACT "contact"
#define CM_AS_IDX_MARK_READ "markChatAsRead"
#define CM_AS_IDX_CLEAR_CHAT "clearChat"
#define CM_AS_IDX_DELETE_CHAT "deleteChat"
#define CM_AS_IDX_DELETE_MESSAGE_FOR_ME "deleteMessageForMe"
#define CM_AS_IDX_PUSH_NAME "setting_pushName"
#define CM_AS_IDX_LABEL_EDIT "label_edit"
#define CM_AS_IDX_LABEL_CHAT "label_jid"
#define CM_AS_IDX_LABEL_MESSAGE "label_message"
#define CM_AS_IDX_USER_STATUS_MUTE "userStatusMute"

typedef struct cm_appstate_mutation {
    const char *collection;
    int is_set;                    /* 1 = SET, 0 = REMOVE */
    int version;                   /* SyncActionData.version */
    uint64_t patch_version;
    const char *const *index;      /* decoded JSON index, e.g. {"mute", "123@s.whatsapp.net"} */
    size_t nindex;
    int64_t timestamp;             /* ms, from the action value */
    int from_full_sync;
    /* the decoded SyncActionValue (protobuf-c: WAWebProtobufSyncAction__SyncActionValue *), valid only
     * during the callback; include "waSyncAction/WAWebProtobufSyncAction.pb-c.h" to read fields. NULL on REMOVE. */
    const void *action;
} cm_appstate_mutation;

typedef struct cm_appstate_sync_evt {
    const char *collection;
    uint64_t version;
    int full_sync;
    int recovery;
    cm_err err;
} cm_appstate_sync_evt;

/* FetchAppState: pulls and applies patches (or a full snapshot) for one collection. */
cm_err cm_client_fetch_app_state(cm_client *c, const char *name, int full_sync, int only_if_not_synced);
/* Fetches every collection (like whatsmeow's handling after receiving app state keys). */
cm_err cm_client_fetch_all_app_state(cm_client *c, int full_sync, int only_if_not_synced);

/* Asks the primary phone for app state keys we lack. */
cm_err cm_client_request_app_state_keys(cm_client *c, const uint8_t *const *key_ids, const size_t *lens, size_t n);

/* Sending mutations (SendAppState + BuildMute, BuildPin, BuildArchive, BuildStar, labels, push name, delete chat). */
cm_err cm_client_app_state_mute(cm_client *c, const cm_jid *chat, int mute, int64_t duration_sec /* 0 = forever */);
cm_err cm_client_app_state_pin(cm_client *c, const cm_jid *chat, int pin);
cm_err cm_client_app_state_archive(cm_client *c, const cm_jid *chat, int archive, int64_t last_msg_ts /* 0 = now */);
cm_err cm_client_app_state_mark_chat_read(cm_client *c, const cm_jid *chat, int read, int64_t last_msg_ts);
cm_err cm_client_app_state_star(cm_client *c, const cm_jid *chat, const cm_jid *sender, const char *msg_id,
                                int from_me, int starred);
cm_err cm_client_app_state_push_name(cm_client *c, const char *name);
cm_err cm_client_app_state_delete_chat(cm_client *c, const cm_jid *chat, int64_t last_msg_ts, int delete_media);
cm_err cm_client_app_state_label_chat(cm_client *c, const cm_jid *chat, const char *label_id, int labeled);
cm_err cm_client_app_state_label_message(cm_client *c, const cm_jid *chat, const char *label_id,
                                         const char *msg_id, int labeled);
cm_err cm_client_app_state_label_edit(cm_client *c, const char *label_id, const char *name, int32_t color, int deleted);

/* Fatal-error recovery: ask the phone for a plaintext snapshot of a collection; the response
 * arrives as a peer message and is applied automatically. */
cm_err cm_client_request_app_state_recovery(cm_client *c, const char *collection);

/* Pure helpers (exposed for tests). */
#define CM_LTHASH_LEN 128
void cm_lthash_subtract_then_add(uint8_t hash[CM_LTHASH_LEN], const uint8_t *const *sub, const size_t *sublen,
                                 size_t nsub, const uint8_t *const *add, const size_t *addlen, size_t nadd);
/* Parses a JSON array of strings; *out is a malloc()ed array of malloc()ed strings. */
cm_err cm_appstate_parse_index(const uint8_t *json, size_t len, char ***out, size_t *n);
char *cm_appstate_marshal_index(const char *const *index, size_t n);

#ifdef __cplusplus
}
#endif
#endif

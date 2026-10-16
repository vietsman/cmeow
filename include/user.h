/* See include/common.h for license and attribution.
 * Port of whatsmeow user.go, presence.go, privacy_settings.go, notification.go, call.go. */
#ifndef CMEOW_USER_H
#define CMEOW_USER_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Extension event kinds (cm_ext_cb). `data` points at the struct named in each comment; strings
 * are only valid during the callback. */
enum {
    CM_EXT_PRESENCE = 300,         /* cm_ext_presence */
    CM_EXT_CHAT_PRESENCE = 301,    /* cm_ext_chat_presence */
    CM_EXT_PICTURE = 302,          /* cm_ext_picture */
    CM_EXT_USER_ABOUT = 303,       /* cm_ext_about */
    CM_EXT_PRIVACY_CHANGED = 304,  /* cm_ext_privacy: a privacy setting changed (re-fetch) */
    CM_EXT_DIRTY = 305,            /* cm_ext_dirty */
    CM_EXT_OFFLINE_SYNC_DONE = 306,/* NULL */
    CM_EXT_PUSH_NAME = 307,        /* cm_ext_about: jid + status = new push name */
    CM_EXT_HISTORY_SYNC = 320,     /* cm_ext_history */
    CM_EXT_CALL_OFFER = 310,       /* cm_ext_call */
    CM_EXT_CALL_ACCEPT = 311,      /* cm_ext_call */
    CM_EXT_CALL_REJECT = 312,      /* cm_ext_call */
    CM_EXT_CALL_TERMINATE = 313,   /* cm_ext_call */
    CM_EXT_CALL_OTHER = 314        /* cm_ext_call (tag in `kind`) */
};

typedef struct { const char *from; int unavailable; int64_t last_seen; } cm_ext_presence;
typedef struct { const char *chat; const char *sender; const char *state; const char *media; } cm_ext_chat_presence;
typedef struct { const char *jid; const char *author; int removed; const char *picture_id; int64_t ts; } cm_ext_picture;
typedef struct { const char *jid; const char *status; int64_t ts; } cm_ext_about;
typedef struct { const char *category; const char *value; } cm_ext_privacy;
typedef struct { const char *type; int64_t ts; } cm_ext_dirty;
typedef struct { const char *call_id; const char *from; const char *creator; int64_t ts; int video; const char *kind; } cm_ext_call;

/* History sync chunk. `history_sync` is a decoded WAWebProtobufsHistorySync__HistorySync* (see
 * src/proto/waHistorySync); it is freed after the callback returns. Push names and phone<->LID
 * mappings inside it are already applied (CM_EXT_PUSH_NAME is emitted per push name). */
typedef struct { const void *history_sync; int sync_type; uint32_t chunk_order; uint32_t progress; } cm_ext_history;

/* ---- presence ---- */
/* state: "composing" or "paused"; media: NULL or "audio". */
cm_err cm_client_send_chat_presence(cm_client *c, const cm_jid *to, const char *state, const char *media);
cm_err cm_client_subscribe_presence(cm_client *c, const cm_jid *jid);

/* ---- users ---- */
typedef struct {
    char *query;  /* the phone number as passed */
    char *jid;    /* NULL if not on WhatsApp */
    int is_in;
    int is_business;
} cm_on_whatsapp;
/* phones like "+15551234567". On success *out is a calloc()ed array of n; free with cm_on_whatsapp_free. */
cm_err cm_client_is_on_whatsapp(cm_client *c, const char *const *phones, size_t n, cm_on_whatsapp **out);
void cm_on_whatsapp_free(cm_on_whatsapp *r, size_t n);

typedef struct { char *jid; char *status; int64_t status_ts; char *picture_id; } cm_user_info;
/* Fetches status and picture id for each JID (non-AD user JIDs). Free with cm_user_info_free. */
cm_err cm_client_get_user_info(cm_client *c, const cm_jid *jids, size_t n, cm_user_info **out);
void cm_user_info_free(cm_user_info *r, size_t n);

typedef struct { char *id; char *url; char *direct_path; } cm_picture_info;
/* jid may be a user or a group. preview != 0 gets the thumbnail. existing_id may be NULL. If the
 * picture is unchanged *out is NULL with CM_OK; no picture also gives NULL. */
cm_err cm_client_get_profile_picture(cm_client *c, const cm_jid *jid, int preview,
                                     const char *existing_id, cm_picture_info **out);
void cm_picture_info_free(cm_picture_info *p);

cm_err cm_client_set_status_message(cm_client *c, const char *msg);

/* ---- blocklist ---- */
/* *jids: array of malloc()ed strings (free each and the array). */
cm_err cm_client_get_blocklist(cm_client *c, char ***jids, size_t *n);
cm_err cm_client_update_blocklist(cm_client *c, const cm_jid *jid, int block);

/* ---- privacy ---- */
typedef struct { char *name; char *value; } cm_privacy_setting;
cm_err cm_client_get_privacy_settings(cm_client *c, cm_privacy_setting **out, size_t *n);
void cm_privacy_settings_free(cm_privacy_setting *s, size_t n);
/* name: "groupadd","last","status","profile","readreceipts","online","calladd"; value: "all",
 * "contacts","contact_blacklist","none","match_last_seen",... */
cm_err cm_client_set_privacy_setting(cm_client *c, const char *name, const char *value);

/* ---- pair with a code ---- */
/* Links this (unpaired, connected) device by phone number instead of QR. phone: international digits,
 * '+' and spaces ignored. client_type: 1 chrome, 2 edge, 3 firefox, 4 ie, 5 opera, 6 safari, 7 electron,
 * 8 uwp, 9 other (0 = chrome). display_name e.g. "Chrome (Linux)" (NULL = that). On success *code is a
 * malloc()ed "ABCD-EFGH" string for the user to type into WhatsApp > Linked devices > Link with phone
 * number. The rest of the handshake runs while the client is pumped; CM_EVT_PAIR_SUCCESS follows. */
cm_err cm_client_pair_phone(cm_client *c, const char *phone, int show_push_notification, int client_type,
                            const char *display_name, char **code);

/* ---- business profile ---- */
typedef struct { char *id; char *name; } cm_biz_category;
typedef struct { char *day; char *mode; int open_min; int close_min; } cm_biz_hours; /* minutes after midnight */
typedef struct {
    char *jid, *address, *description, *email;
    char **websites;           size_t nwebsites;
    cm_biz_category *categories; size_t ncategories;
    char *timezone;
    cm_biz_hours *hours;       size_t nhours;
} cm_business_profile;
/* *out is calloc()ed; CM_OK with *out == NULL when the user has no business profile. */
cm_err cm_client_get_business_profile(cm_client *c, const cm_jid *jid, cm_business_profile **out);
void cm_business_profile_free(cm_business_profile *p);

/* ---- calls ---- */
cm_err cm_client_reject_call(cm_client *c, const cm_jid *from, const char *call_id);

#ifdef __cplusplus
}
#endif
#endif

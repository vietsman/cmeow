/* See include/common.h for license and attribution.
 * Port of whatsmeow send.go, retry.go, receipt.go, group.go, broadcast.go. */
#ifndef CMEOW_MESSAGING_H
#define CMEOW_MESSAGING_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ext event kinds (cm_ext_cb) */
enum {
    CM_EXT_RECEIPT = 100,        /* cm_receipt_evt */
    CM_EXT_GROUP_INFO = 500,     /* cm_group_notif: action = "subject","description","announce","locked","ephemeral","create" */
    CM_EXT_GROUP_PARTICIPANTS,   /* cm_group_notif: action = "add","remove","promote","demote","leave" */
    CM_EXT_GROUP_LINK            /* cm_group_notif: action = "invite" ... */
};

typedef struct cm_receipt_evt {
    const cm_jid *chat, *sender;
    const char *const *ids;
    size_t nids;
    int64_t timestamp;
    const char *type; /* "delivery" (empty on the wire), "read", "played", "sender", "inactive", ... */
    int is_group, is_from_me;
} cm_receipt_evt;

typedef struct cm_group_notif {
    const cm_jid *group, *author;
    const char *action;
    int64_t timestamp;
    const cm_jid *participants;
    size_t nparticipants;
    const char *text; /* new subject / description, or NULL */
    int flag;         /* announce/locked on/off; ephemeral timer */
} cm_group_notif;

/* -------------------------------------------------------------- sending */
typedef struct cm_send_opts {
    const char *id;     /* NULL = generate */
    const char *edit;   /* edit attribute: "1" edit, "7" sender revoke, "8" admin revoke, or NULL */
    int timeout_ms;     /* wait for server ack (0 = 75000) */
} cm_send_opts;

typedef struct cm_send_resp {
    char *id;           /* malloc()ed */
    int64_t timestamp;  /* server ack time */
    char *phash;        /* group participant hash we used (malloc()ed or NULL) */
} cm_send_resp;
void cm_send_resp_free(cm_send_resp *r);

/* Sends a serialized waE2E.Message to a user or group JID. */
cm_err cm_client_send_message(cm_client *c, const cm_jid *to, const uint8_t *msg, size_t len,
                              const cm_send_opts *opts, cm_send_resp *resp);
/* status@broadcast or a broadcast list: the caller supplies the recipients */
cm_err cm_client_send_broadcast(cm_client *c, const cm_jid *bcast, const cm_jid *recipients, size_t n,
                                const uint8_t *msg, size_t len, const cm_send_opts *opts, cm_send_resp *resp);
cm_err cm_client_send_group_text(cm_client *c, const cm_jid *group, const char *text, char **msg_id);

/* Message builders: each returns a malloc()ed serialized waE2E.Message. */
uint8_t *cm_message_build_text(const char *text, size_t *len);
uint8_t *cm_message_build_reply(const char *text, const char *quoted_id, const cm_jid *quoted_sender,
                                const uint8_t *quoted_msg, size_t quoted_len, size_t *len);
uint8_t *cm_message_build_reaction(const cm_jid *chat, const cm_jid *sender, const char *target_id,
                                   int from_me, const char *emoji /* "" removes */, size_t *len);
uint8_t *cm_message_build_revoke(const cm_jid *chat, const cm_jid *sender, const char *target_id,
                                 int from_me, size_t *len);
uint8_t *cm_message_build_edit(const cm_jid *chat, const char *target_id, const char *new_text, size_t *len);
cm_err cm_client_send_revoke(cm_client *c, const cm_jid *chat, const cm_jid *sender,
                             const char *target_id, int from_me, char **msg_id);
cm_err cm_client_send_edit(cm_client *c, const cm_jid *chat, const char *target_id, const char *new_text,
                           char **msg_id);
cm_err cm_client_send_reaction(cm_client *c, const cm_jid *chat, const cm_jid *sender,
                               const char *target_id, int from_me, const char *emoji, char **msg_id);

/* Message to our own primary phone (category=peer): app state key requests, recovery, ... */
cm_err cm_client_send_peer_message(cm_client *c, const uint8_t *msg, size_t len, const char *push_priority,
                                   char **msg_id);
/* <receipt type=... to=own> for protocol messages ("peer_msg", "hist_sync") */
cm_err cm_client_send_protocol_receipt(cm_client *c, const char *id, const char *type);

/* Receipts */
typedef enum { CM_RECEIPT_READ, CM_RECEIPT_PLAYED } cm_receipt_kind;
cm_err cm_client_mark_read(cm_client *c, const cm_jid *chat, const cm_jid *sender,
                           const char *const *ids, size_t nids, int64_t timestamp, cm_receipt_kind kind);

/* ---------------------------------------------------------------- groups */
typedef struct cm_group_participant {
    cm_jid jid;     /* as addressed in the group (may be a LID) */
    cm_jid phone;   /* phone-number JID if the server gave one (else empty) */
    int is_admin, is_super_admin;
} cm_group_participant;

typedef struct cm_group_info {
    cm_jid jid, owner;
    char *name, *topic, *topic_id, *addressing_mode;
    int64_t created, name_set_at, topic_set_at;
    size_t nparticipants;
    cm_group_participant *participants;
    int is_announce, is_locked, is_ephemeral, is_join_approval;
    uint32_t disappearing_timer;
} cm_group_info;
void cm_group_info_free(cm_group_info *g);

typedef struct cm_group_list { cm_group_info *v; size_t n; } cm_group_list;
void cm_group_list_free(cm_group_list *l);

cm_err cm_client_get_group_info(cm_client *c, const cm_jid *group, cm_group_info *out);
cm_err cm_client_get_joined_groups(cm_client *c, cm_group_list *out);
cm_err cm_client_create_group(cm_client *c, const char *name, const cm_jid *participants, size_t n,
                              cm_group_info *out);
typedef enum { CM_GP_ADD, CM_GP_REMOVE, CM_GP_PROMOTE, CM_GP_DEMOTE } cm_participant_action;
/* per-participant result codes (HTTP-like, "200"=ok) are not returned; failures give CM_ERR_PROTO */
cm_err cm_client_update_group_participants(cm_client *c, const cm_jid *group, const cm_jid *participants,
                                           size_t n, cm_participant_action action);
cm_err cm_client_set_group_name(cm_client *c, const cm_jid *group, const char *name);
/* topic == NULL or "" deletes the description */
cm_err cm_client_set_group_topic(cm_client *c, const cm_jid *group, const char *topic);
cm_err cm_client_set_group_announce(cm_client *c, const cm_jid *group, int announce);
cm_err cm_client_set_group_locked(cm_client *c, const cm_jid *group, int locked);
cm_err cm_client_set_group_ephemeral(cm_client *c, const cm_jid *group, uint32_t seconds);
cm_err cm_client_get_group_invite_link(cm_client *c, const cm_jid *group, int reset, char **link);
cm_err cm_client_join_group_with_link(cm_client *c, const char *link_or_code, cm_jid *joined);
cm_err cm_client_leave_group(cm_client *c, const cm_jid *group);

#ifdef __cplusplus
}
#endif
#endif

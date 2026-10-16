/* See common.h for license and attribution. Port of whatsmeow/types/jid.go */
#ifndef CMEOW_JID_H
#define CMEOW_JID_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Known JID servers on WhatsApp. */
#define CM_SERVER_DEFAULT_USER "s.whatsapp.net"
#define CM_SERVER_GROUP        "g.us"
#define CM_SERVER_LEGACY_USER  "c.us"
#define CM_SERVER_BROADCAST    "broadcast"
#define CM_SERVER_HIDDEN_USER  "lid"
#define CM_SERVER_MESSENGER    "msgr"
#define CM_SERVER_INTEROP      "interop"
#define CM_SERVER_NEWSLETTER   "newsletter"
#define CM_SERVER_HOSTED       "hosted"
#define CM_SERVER_HOSTED_LID   "hosted.lid"
#define CM_SERVER_BOT          "bot"

/* Agent / domain types. */
#define CM_DOMAIN_WHATSAPP   0
#define CM_DOMAIN_LID        1
#define CM_DOMAIN_HOSTED     128
#define CM_DOMAIN_HOSTED_LID 129

/*
 * A WhatsApp user ID. `user` and `server` are heap strings owned by the
 * struct; NULL means the empty string. Zero-initialise (or cm_jid_init)
 * before use and cm_jid_free when done. Copy with cm_jid_copy, never by
 * plain struct assignment (that would alias the strings).
 */
typedef struct cm_jid {
    char *user;
    char *server;
    uint8_t raw_agent;
    uint16_t device;
    uint16_t integrator;
} cm_jid;

void cm_jid_init(cm_jid *j);
void cm_jid_free(cm_jid *j);

/* NewJID: regular JID pair. Replaces any previous contents. */
cm_err cm_jid_set(cm_jid *j, const char *user, const char *server);
/* NewADJID: user + agent + device (server is derived from the agent). */
cm_err cm_jid_set_ad(cm_jid *j, const char *user, uint8_t agent, uint8_t device);
cm_err cm_jid_copy(cm_jid *dst, const cm_jid *src);

/* ParseJID. Accepts regular and AD JIDs. */
cm_err cm_jid_parse(cm_jid *out, const char *s);

/* Allocated strings, free with free(). */
cm_err cm_jid_to_string(const cm_jid *j, char **out);
cm_err cm_jid_to_ad_string(const cm_jid *j, char **out);
cm_err cm_jid_signal_address_user(const cm_jid *j, char **out);

/* ToNonAD: copy without agent and device. */
cm_err cm_jid_to_non_ad(cm_jid *out, const cm_jid *j);

uint8_t cm_jid_actual_agent(const cm_jid *j);
int cm_jid_is_empty(const cm_jid *j);
int cm_jid_is_broadcast_list(const cm_jid *j);
int cm_jid_is_bot(const cm_jid *j);
int cm_jid_equal(const cm_jid *a, const cm_jid *b);

/* NULL-safe accessors returning "" for unset strings. */
const char *cm_jid_user(const cm_jid *j);
const char *cm_jid_server(const cm_jid *j);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_JID_H */

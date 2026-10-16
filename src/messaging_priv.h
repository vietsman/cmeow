/* Internal to the messaging module. */
#ifndef CMEOW_MESSAGING_PRIV_H
#define CMEOW_MESSAGING_PRIV_H

#include "client_priv.h"
#include "messaging.h"

typedef struct cmi_jidlist {
    cm_jid *v;
    size_t n, cap;
} cmi_jidlist;
cm_err cmi_jl_add(cmi_jidlist *l, const cm_jid *j);
void cmi_jl_free(cmi_jidlist *l);

void cmi_free_resp(cm_node *r);
void cmi_addr_of(const cm_jid *j, char **name, signal_protocol_address *a);
char *cmi_gen_msg_id(void);
cm_err cmi_set_attr_copy(cm_node *dst, const cm_node *src, const char *from_key, const char *to_key);

/* device list with a 1h cache; users must be non-AD */
cm_err cmi_get_devices(cm_client *c, const cm_jid *users, size_t n, cmi_jidlist *out);
void cmi_devices_forget(cm_client *c, const cm_jid *user);

/* prekeys.c */
cm_err cmi_process_bundle(cm_client *c, const cm_jid *j, const cm_node *user);

struct cmi_mstate {
    struct { char *key; cmi_jidlist devs; int64_t exp; } *dev;
    size_t ndev;
    struct { char *id; uint8_t *msg; size_t len; } sent[64];
    size_t sent_next;
    struct { char *k; int v; } *retries;
    size_t nret;
    char **skdm;
    size_t nskdm, capskdm;
    struct { char *key; cm_group_info gi; int64_t exp; } *groups;
    size_t ngroups;
};
struct cmi_mstate *cmi_ms(cm_client *c);

/* send.c */
cm_err cmi_encrypt_for(cm_client *c, const uint8_t *plain, size_t plen, const cm_jid *to, const char *mediatype,
                       cm_node *enc_out, int *is_prekey);
cm_err cmi_pad(const uint8_t *in, size_t len, uint8_t **out, size_t *olen);
const char *cmi_msg_type(const void *e2e_msg, const char **mediatype);

/* messaging.c (state) */
void cmi_remember_sent(cm_client *c, const char *id, const cm_jid *chat, const uint8_t *msg, size_t len);
const uint8_t *cmi_find_sent(cm_client *c, const char *id, size_t *len);
int cmi_skdm_has(cm_client *c, const char *group, const cm_jid *dev);
void cmi_skdm_mark(cm_client *c, const char *group, const cm_jid *dev);
void cmi_skdm_reset(cm_client *c, const char *group);
int cmi_retry_count_inc(cm_client *c, const char *key);

/* groups.c */
cm_err cmi_group_get(cm_client *c, const cm_jid *g, const cm_group_info **out); /* cached, borrowed */
void cmi_group_forget(cm_client *c, const cm_jid *g);
cm_err cmi_parse_group_node(const cm_node *n, cm_group_info *out);

/* retry.c */
void cmi_send_retry_receipt(cm_client *c, const cm_node *msg_node, int force_identity);
void cmi_handle_retry_receipt(cm_client *c, const cm_node *receipt);

#endif

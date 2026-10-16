/* See include/common.h for license and attribution. */
#ifndef CMEOW_STORE_H
#define CMEOW_STORE_H

#include "crypto.h"
#include "jid.h"

#include <signal_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Port of whatsmeow/store (Device + the in-memory equivalents of the
 * Identity/Session/PreKey/SenderKey/AppStateSyncKey stores) together with the
 * glue that exposes them to libsignal-protocol-c.
 *
 * Persistence: cm_device_save()/cm_device_load() write the whole device to a
 * file (atomically, via rename). Callers wanting a database can replace those
 * two functions; everything else works on the in-memory tables.
 */

typedef struct cm_kv {
    char *key;
    uint8_t *val;
    size_t len;
    uint32_t flag;
} cm_kv;

typedef struct cm_kvmap {
    cm_kv *e;
    size_t n, cap;
} cm_kvmap;

cm_kv *cm_kvmap_find(const cm_kvmap *m, const char *key);
/* inserts or replaces; keeps flag when replacing */
cm_err cm_kvmap_put(cm_kvmap *m, const char *key, const uint8_t *val, size_t len);
int cm_kvmap_del(cm_kvmap *m, const char *key);
void cm_kvmap_free(cm_kvmap *m);

typedef struct cm_prekey {
    uint32_t id;
    cm_keypair key;
    uint8_t signature[64];
    int has_signature;
} cm_prekey;

typedef struct cm_device {
    cm_keypair noise_key;
    cm_keypair identity_key;
    cm_prekey signed_prekey;
    uint32_t registration_id;
    uint8_t adv_secret_key[32];

    int has_id;
    cm_jid id;
    cm_jid lid;
    uint8_t *account; /* marshalled waAdv.ADVSignedDeviceIdentity */
    size_t account_len;
    char *platform;
    char *business_name;
    char *push_name;

    cm_kvmap identities;     /* "name.device" -> 32-byte key */
    cm_kvmap sessions;       /* "name.device" -> libsignal session record */
    cm_kvmap sender_keys;    /* "group::name.device" -> record */
    cm_kvmap app_state_keys; /* hex(key id) -> data */
    cm_kvmap prekeys;        /* decimal id -> priv[32] pub[32]; flag = uploaded */
    cm_kvmap tc_tokens;      /* user -> ts8 BE || token (trusted-contact privacy tokens) */
    cm_kvmap lid_map;        /* "p:<pn user>" -> lid user, "l:<lid user>" -> pn user (NUL-terminated values) */
    uint32_t next_prekey_id;

    signal_context *sctx;
    signal_protocol_store_context *sstore;
} cm_device;

/* store.NewDevice: fresh noise/identity keys, signed prekey #1, registration ID. */
cm_err cm_device_new(cm_device **out);
void cm_device_free(cm_device *d);

/* Wires the tables into libsignal (creates sctx/sstore). Called by new/load. */
cm_err cm_device_signal_init(cm_device *d);

cm_err cm_device_save(const cm_device *d, const char *path);
cm_err cm_device_load(cm_device **out, const char *path);

/* PreKeyStore.GetOrGenPreKeys: up to count unuploaded prekeys, generating as needed.
 * out is malloc()ed array of count entries. */
cm_err cm_device_get_or_gen_prekeys(cm_device *d, uint32_t count, cm_prekey **out, uint32_t *n);
cm_err cm_device_mark_prekeys_uploaded(cm_device *d, uint32_t up_to_id);
size_t cm_device_uploaded_prekey_count(const cm_device *d);

/* Sets the logged-in identity after pairing. */
cm_err cm_device_set_id(cm_device *d, const cm_jid *id);

/* LID <-> phone-number user mapping. Returns 1 if the mapping was new or changed. Getters return a
 * borrowed string or NULL. */
int cm_device_lid_put(cm_device *d, const char *pn_user, const char *lid_user);
const char *cm_device_lid_for_pn(const cm_device *d, const char *pn_user);
const char *cm_device_pn_for_lid(const cm_device *d, const char *lid_user);

/* "name.device" string used as session / identity key. */
cm_err cm_signal_address_string(const cm_jid *j, char **out);

/* store.Device.GetClientPayload: marshals waWa6.ClientPayload (login if has_id, else registration).
 * out is malloc()ed. */
/* store.SetWAVersion */
void cm_set_wa_version(uint32_t a, uint32_t b, uint32_t c);

cm_err cm_device_client_payload(const cm_device *d, uint8_t **out, size_t *len);

#ifdef __cplusplus
}
#endif
#endif

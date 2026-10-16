/* See common.h for license and attribution. Port of whatsmeow/handshake.go.
 * Transport-free: the caller moves the byte strings over the frame socket. */
#ifndef CMEOW_HANDSHAKE_H
#define CMEOW_HANDSHAKE_H

#include "common.h"
#include "crypto.h"
#include "noise.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_NOISE_HANDSHAKE_RESPONSE_TIMEOUT_SECS 20
#define CM_WA_CERT_ISSUER_SERIAL 0

/* WACertPubKey: the root key that signs the server's noise certificate chain. */
extern const uint8_t cm_wa_cert_pubkey[32];

/* XEdDSA (Curve25519 signatures) via libsignal-protocol-c.
 * sign: priv is a curve25519 private key; msg any length. */
cm_err cm_xeddsa_sign(const uint8_t priv[32], const void *msg, size_t len, uint8_t sig[64]);
/* Returns CM_OK, CM_ERR_AUTH for a bad signature. */
cm_err cm_xeddsa_verify(const uint8_t pub[32], const void *msg, size_t len, const uint8_t sig[64]);

/* Human readable reason for the last failure (mirrors whatsmeow's error text).
 * Optional: pass NULL to ignore. */
typedef struct cm_hs_error {
    char message[192];
} cm_hs_error;

typedef struct cm_handshake {
    cm_noise_hs nh;
    cm_keypair ephemeral;
    uint8_t header[CM_CONN_HEADER_LEN];
} cm_handshake;

/*
 * Step 1 (Client.doHandshake up to the first SendFrame): starts the noise
 * state with the connection header, authenticates our ephemeral public key
 * and marshals the ClientHello HandshakeMessage. *out is malloc()ed.
 *
 * The connection header (WAConnHeader) must be prefixed to this first frame by
 * the frame socket (cm_frame_encode with header).
 */
cm_err cm_handshake_begin(cm_handshake *hs, const cm_keypair *ephemeral,
                          uint8_t **out, size_t *out_len);

/*
 * Step 2: processes the ServerHello frame, verifies the server's certificate
 * chain, and produces the ClientFinish frame (*out, malloc()ed) plus the
 * transport keys for the post-handshake noise socket.
 *
 *  noise_key       the client's static noise key pair (Store.NoiseKey)
 *  client_payload  the marshalled waWa6.ClientPayload (login or registration)
 *  now_unix        current time, for certificate validity
 *  root_pub        key that must have signed the intermediate certificate; NULL
 *                  means the real WhatsApp key (cm_wa_cert_pubkey)
 */
cm_err cm_handshake_finish(cm_handshake *hs, const uint8_t *server_hello, size_t hello_len,
                           const cm_keypair *noise_key,
                           const uint8_t *client_payload, size_t payload_len,
                           int64_t now_unix, const uint8_t *root_pub,
                           uint8_t **out, size_t *out_len,
                           cm_noise_transport *transport, cm_hs_error *err);

/* verifyServerCert, exposed for tests. */
cm_err cm_verify_server_cert(const uint8_t *cert, size_t cert_len,
                             const uint8_t static_key[32], int64_t now_unix,
                             const uint8_t *root_pub, cm_hs_error *err);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_HANDSHAKE_H */

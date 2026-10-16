/* See common.h for license and attribution.
 * Port of whatsmeow/socket: noisehandshake.go, the crypto half of
 * noisesocket.go and the framing half of framesocket.go. Transport-free. */
#ifndef CMEOW_NOISE_H
#define CMEOW_NOISE_H

#include "buf.h"
#include "common.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* socket/constants.go */
#define CM_WA_ORIGIN "https://web.whatsapp.com"
#define CM_WA_URL "wss://web.whatsapp.com/ws/chat"
#define CM_WA_MAGIC_VALUE 6
#define CM_NOISE_START_PATTERN "Noise_XX_25519_AESGCM_SHA256\0\0\0\0"
#define CM_NOISE_START_PATTERN_LEN 32 /* contains NULs, so no strlen */
#define CM_FRAME_MAX_SIZE (1u << 24)
#define CM_FRAME_LENGTH_SIZE 3
#define CM_CONN_HEADER_LEN 4

/* WAConnHeader = {'W','A', WAMagicValue, DictVersion}. */
void cm_conn_header(uint8_t out[CM_CONN_HEADER_LEN]);

/* ---- NoiseHandshake ---- */
typedef struct cm_noise_hs {
    uint8_t hash[CM_SHA256_LEN];
    uint8_t salt[CM_SHA256_LEN];
    uint8_t key[CM_GCM_KEY_LEN];
    uint32_t counter;
} cm_noise_hs;

/* Start: a 32 byte pattern is used as the initial hash as-is, anything else is
 * hashed first. Then `header` is authenticated. */
cm_err cm_noise_start(cm_noise_hs *nh, const void *pattern, size_t pattern_len,
                      const void *header, size_t header_len);
cm_err cm_noise_authenticate(cm_noise_hs *nh, const void *data, size_t len);
/* out must hold len + 16 (encrypt) / len - 16 (decrypt). */
cm_err cm_noise_encrypt(cm_noise_hs *nh, const void *pt, size_t len, uint8_t *out);
cm_err cm_noise_decrypt(cm_noise_hs *nh, const void *ct, size_t len, uint8_t *out);
cm_err cm_noise_mix_shared_secret(cm_noise_hs *nh, const uint8_t priv[32], const uint8_t pub[32]);
cm_err cm_noise_mix_into_key(cm_noise_hs *nh, const void *data, size_t len);

/* ---- transport phase (NoiseSocket crypto) ---- */
typedef struct cm_noise_transport {
    uint8_t write_key[CM_GCM_KEY_LEN];
    uint8_t read_key[CM_GCM_KEY_LEN];
    uint32_t write_counter;
    uint32_t read_counter;
} cm_noise_transport;

/* NoiseHandshake.Finish: derives the final write/read keys. */
cm_err cm_noise_finish(const cm_noise_hs *nh, cm_noise_transport *t);
/* Seal: out must hold len + 16. Increments the write counter. */
cm_err cm_noise_transport_seal(cm_noise_transport *t, const void *pt, size_t len, uint8_t *out);
/* Open: out must hold len - 16. Like Go, the read counter advances even when
 * decryption fails. Returns CM_ERR_AUTH on a bad tag. */
cm_err cm_noise_transport_open(cm_noise_transport *t, const void *ct, size_t len, uint8_t *out);

/* ---- frame socket framing ---- */

/*
 * Appends one frame (optional connection header, 3 byte big-endian length,
 * payload) to `out`. Fails with CM_ERR_TOO_LARGE for len >= CM_FRAME_MAX_SIZE.
 * Pass header == NULL once the header has been sent.
 */
cm_err cm_frame_encode(cm_buf *out, const uint8_t *header, size_t header_len,
                       const void *data, size_t len);

/* Called once per complete frame; `frame` is only valid during the call. A
 * non-OK return aborts parsing and is returned from cm_frame_parser_feed. */
typedef cm_err (*cm_frame_cb)(void *user, const uint8_t *frame, size_t len);

typedef struct cm_frame_parser {
    uint8_t hdr[CM_FRAME_LENGTH_SIZE];
    size_t hdr_len;
    uint8_t *body; /* only used when a frame spans several feeds */
    size_t body_len;
    size_t body_got;
    int in_body;
} cm_frame_parser;

void cm_frame_parser_init(cm_frame_parser *p);
void cm_frame_parser_free(cm_frame_parser *p);
/* Equivalent to FrameSocket.processData. */
cm_err cm_frame_parser_feed(cm_frame_parser *p, const uint8_t *data, size_t len,
                            cm_frame_cb cb, void *user);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_NOISE_H */

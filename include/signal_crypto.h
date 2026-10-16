/* See common.h for license and attribution.
 * OpenSSL 3.x backed crypto provider for libsignal-protocol-c. */
#ifndef CMEOW_SIGNAL_CRYPTO_H
#define CMEOW_SIGNAL_CRYPTO_H

#include "signal_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fills in a provider whose callbacks use OpenSSL libcrypto. */
void cm_signal_crypto_provider(signal_crypto_provider *out);

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_SIGNAL_CRYPTO_H */

/* See common.h for license and attribution. Port of whatsmeow/binary/token */
#ifndef CMEOW_TOKEN_H
#define CMEOW_TOKEN_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Type tokens used in the binary XML representation. */
enum {
    CM_TOK_LIST_EMPTY = 0,
    CM_TOK_DICTIONARY_0 = 236,
    CM_TOK_DICTIONARY_1 = 237,
    CM_TOK_DICTIONARY_2 = 238,
    CM_TOK_DICTIONARY_3 = 239,
    CM_TOK_INTEROP_JID = 245,
    CM_TOK_FB_JID = 246,
    CM_TOK_AD_JID = 247,
    CM_TOK_LIST_8 = 248,
    CM_TOK_LIST_16 = 249,
    CM_TOK_JID_PAIR = 250,
    CM_TOK_HEX_8 = 251,
    CM_TOK_BINARY_8 = 252,
    CM_TOK_BINARY_20 = 253,
    CM_TOK_BINARY_32 = 254,
    CM_TOK_NIBBLE_8 = 255
};

#define CM_TOK_PACKED_MAX 127

/* Version of the token dictionaries (sent when connecting). */
extern const int cm_dict_version;

/* Single byte tokens: index == token byte. Entry 0 is the empty string. */
extern const char *const cm_single_tokens[];
extern const size_t cm_single_token_count;

struct cm_dict {
    const char *const *tokens;
    size_t count;
};
extern const struct cm_dict cm_double_dicts[4];

/* GetDoubleToken: NULL if out of range. */
const char *cm_token_get_double(int dict, int index);

/* IndexOfSingleToken: returns 1 and sets *idx if found. */
int cm_token_index_single(const char *tok, uint8_t *idx);
/* IndexOfDoubleByteToken: returns 1 and sets *dict, *idx if found. */
int cm_token_index_double(const char *tok, uint8_t *dict, uint8_t *idx);

/* Sorted reverse-lookup tables emitted by tools/gen_tokens.py. */
struct cm_tok_single {
    const char *s;
    uint8_t idx;
};
struct cm_tok_double {
    const char *s;
    uint8_t dict;
    uint8_t idx;
};
extern const struct cm_tok_single cm_tok_single_sorted[];
extern const size_t cm_tok_single_sorted_len;
extern const struct cm_tok_double cm_tok_double_sorted[];
extern const size_t cm_tok_double_sorted_len;

#ifdef __cplusplus
}
#endif

#endif /* CMEOW_TOKEN_H */

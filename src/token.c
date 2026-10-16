/* See include/common.h for license and attribution. Port of whatsmeow/binary/token */
#include "token.h"

#include <stdlib.h>
#include <string.h>

const char *cm_token_get_double(int dict, int index)
{
    if (dict < 0 || dict >= 4)
        return NULL;
    if (index < 0 || (size_t)index >= cm_double_dicts[dict].count)
        return NULL;
    return cm_double_dicts[dict].tokens[index];
}

static int cmp_single(const void *key, const void *elem)
{
    return strcmp((const char *)key, ((const struct cm_tok_single *)elem)->s);
}

static int cmp_double(const void *key, const void *elem)
{
    return strcmp((const char *)key, ((const struct cm_tok_double *)elem)->s);
}

int cm_token_index_single(const char *tok, uint8_t *idx)
{
    const struct cm_tok_single *r = (const struct cm_tok_single *)bsearch(
        tok, cm_tok_single_sorted, cm_tok_single_sorted_len,
        sizeof(cm_tok_single_sorted[0]), cmp_single);

    if (r == NULL)
        return 0;
    *idx = r->idx;
    return 1;
}

int cm_token_index_double(const char *tok, uint8_t *dict, uint8_t *idx)
{
    const struct cm_tok_double *r = (const struct cm_tok_double *)bsearch(
        tok, cm_tok_double_sorted, cm_tok_double_sorted_len,
        sizeof(cm_tok_double_sorted[0]), cmp_double);

    if (r == NULL)
        return 0;
    *dict = r->dict;
    *idx = r->idx;
    return 1;
}

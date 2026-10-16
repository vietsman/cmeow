/* Appstate: LTHash add/subtract algebra and JSON index round trip. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "appstate.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

int main(void)
{
    uint8_t h0[CM_LTHASH_LEN], h1[CM_LTHASH_LEN], z[CM_LTHASH_LEN];
    const uint8_t a[32] = {1, 2, 3}, b[32] = {9, 8, 7};
    const uint8_t *pa[2] = {a, b};
    size_t la[2] = {32, 32};
    const char *idx[2] = {"mute", "123@s.whatsapp.net"};
    char *js, **back = NULL;
    size_t n = 0;

    memset(h0, 0, sizeof h0);
    memset(z, 0, sizeof z);
    cm_lthash_subtract_then_add(h0, NULL, NULL, 0, pa, la, 2);
    CHECK(memcmp(h0, z, sizeof z) != 0);
    memcpy(h1, h0, sizeof h1);
    cm_lthash_subtract_then_add(h1, pa, la, 2, NULL, NULL, 0);
    CHECK(memcmp(h1, z, sizeof z) == 0); /* add then subtract returns to zero */
    {   /* order independent */
        const uint8_t *pr[2] = {b, a};
        size_t lr[2] = {32, 32};
        uint8_t h2[CM_LTHASH_LEN];

        memset(h2, 0, sizeof h2);
        cm_lthash_subtract_then_add(h2, NULL, NULL, 0, pr, lr, 2);
        CHECK(memcmp(h2, h0, sizeof h2) == 0);
    }
    js = cm_appstate_marshal_index(idx, 2);
    CHECK(js && strcmp(js, "[\"mute\",\"123@s.whatsapp.net\"]") == 0);
    CHECK(cm_appstate_parse_index((const uint8_t *)js, strlen(js), &back, &n) == CM_OK && n == 2 &&
          strcmp(back[0], "mute") == 0 && strcmp(back[1], idx[1]) == 0);
    while (n > 0)
        free(back[--n]);
    free(back);
    free(js);
    printf("test_appstate: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}

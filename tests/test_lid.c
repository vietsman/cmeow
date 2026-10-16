/* LID<->PN mapping: sessions/identities migrate to the LID address, mapping persists. */
#include <stdio.h>
#include <string.h>

#include "client_priv.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

int main(void)
{
    cm_client c;
    cm_device *d2 = NULL;
    const uint8_t rec[3] = {1, 2, 3};
    cm_jid pn, out;

    memset(&c, 0, sizeof c);
    CHECK(cm_device_new(&c.dev) == CM_OK);
    cm_kvmap_put(&c.dev->sessions, "111.0", rec, 3);
    cm_kvmap_put(&c.dev->sessions, "111.5", rec, 3);
    cm_kvmap_put(&c.dev->sessions, "1112.0", rec, 3); /* different user, must not move */
    cm_kvmap_put(&c.dev->identities, "111.0", rec, 3);
    cmi_lid_learn(&c, "111", "222");
    CHECK(cm_kvmap_find(&c.dev->sessions, "222_1.0") && cm_kvmap_find(&c.dev->sessions, "222_1.5"));
    CHECK(!cm_kvmap_find(&c.dev->sessions, "111.0") && !cm_kvmap_find(&c.dev->sessions, "111.5"));
    CHECK(cm_kvmap_find(&c.dev->sessions, "1112.0") != NULL);
    CHECK(cm_kvmap_find(&c.dev->identities, "222_1.0") != NULL);
    cm_jid_init(&pn);
    cm_jid_init(&out);
    cm_jid_set(&pn, "111", CM_SERVER_DEFAULT_USER);
    pn.device = 3;
    CHECK(cmi_lid_for_pn(&c, &pn, &out) == 1 && strcmp(out.user, "222") == 0 && out.device == 3 &&
          strcmp(out.server, CM_SERVER_HIDDEN_USER) == 0);
    CHECK(strcmp(cm_device_pn_for_lid(c.dev, "222"), "111") == 0);
    CHECK(cm_device_save(c.dev, "/tmp/test_lid.dev") == CM_OK && cm_device_load(&d2, "/tmp/test_lid.dev") == CM_OK &&
          cm_device_lid_for_pn(d2, "111") && strcmp(cm_device_lid_for_pn(d2, "111"), "222") == 0);
    remove("/tmp/test_lid.dev");
    cm_jid_free(&pn);
    cm_jid_free(&out);
    cm_device_free(d2);
    cm_device_free(c.dev);
    printf("test_lid: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}

/* See include/common.h for license and attribution. */
#include "client_priv.h"

#include <string.h>

/* Routes nodes the core client does not handle to the module that does. */
int cmi_ext_dispatch(cm_client *c, const cm_node *n)
{
    const char *t = n->tag;

    if (strcmp(t, "notification") == 0 || strcmp(t, "presence") == 0 || strcmp(t, "chatstate") == 0 ||
        strcmp(t, "ib") == 0 || strcmp(t, "call") == 0) {
        cmi_user_handle_node(c, n);
        return 1;
    }
    return 0;
}

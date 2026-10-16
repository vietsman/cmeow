#ifndef CMEOW_MEDIA_PRIV_H
#define CMEOW_MEDIA_PRIV_H
#include "client_priv.h"
#include "media.h"

/* Parses a <notification type="mediaretry"> and emits CM_EXT_MEDIA_RETRY. */
void cmi_media_handle_retry_notification(cm_client *c, const cm_node *n);
#endif

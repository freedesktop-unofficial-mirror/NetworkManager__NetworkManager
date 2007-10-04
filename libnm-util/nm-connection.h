#ifndef NM_CONNECTION_H
#define NM_CONNECTION_H

#include <glib.h>
#include <glib-object.h>
#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_CONNECTION            (nm_connection_get_type ())
#define NM_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTION, NMConnection))
#define NM_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CONNECTION, NMConnectionClass))
#define NM_IS_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTION))
#define NM_IS_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_CONNECTION))
#define NM_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CONNECTION, NMConnectionClass))

typedef struct {
	GObject parent;
} NMConnection;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*secrets_updated) (NMConnection *connection, const char * setting);
} NMConnectionClass;

GType nm_connection_get_type (void);

NMConnection *nm_connection_new           (void);
NMConnection *nm_connection_new_from_hash (GHashTable *hash);
void          nm_connection_add_setting   (NMConnection *connection,
										   NMSetting    *setting);

NMSetting    *nm_connection_get_setting   (NMConnection *connection,
										   const char   *setting_name);

gboolean      nm_connection_compare       (NMConnection *connection,
										   NMConnection *other);

gboolean      nm_connection_verify        (NMConnection *connection);

const char *  nm_connection_need_secrets  (NMConnection *connection);

void          nm_connection_clear_secrets (NMConnection *connection);

void          nm_connection_update_secrets (NMConnection *connection,
                                            const char *setting_name,
                                            GHashTable *secrets);

void          nm_connection_for_each_setting_value (NMConnection *connection,
                                                     NMSettingValueIterFn func,
                                                     gpointer user_data);

GHashTable   *nm_connection_to_hash       (NMConnection *connection);
void          nm_connection_dump          (NMConnection *connection);


void nm_setting_parser_register   (const char *name,
								   NMSettingCreateFn creator);

void nm_setting_parser_unregister (const char *name);

G_END_DECLS

#endif /* NM_CONNECTION_H */

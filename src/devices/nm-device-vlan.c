/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2011 - 2012 Red Hat, Inc.
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <sys/socket.h>

#include "nm-device-vlan.h"
#include "nm-manager.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-enum-types.h"
#include "nm-dbus-manager.h"
#include "nm-connection-provider.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-manager.h"
#include "nm-core-internal.h"

#include "nm-device-vlan-glue.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceVlan);

G_DEFINE_TYPE (NMDeviceVlan, nm_device_vlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VLAN, NMDeviceVlanPrivate))

typedef struct {
	char *initial_hw_addr;

	gboolean disposed;
	gboolean invalid;

	NMDevice *parent;
	guint parent_state_id;

	int vlan_id;
} NMDeviceVlanPrivate;

enum {
	PROP_0,
	PROP_PARENT,
	PROP_VLAN_ID,

	PROP_INT_PARENT_DEVICE,

	LAST_PROP
};

/******************************************************************/

static void
update_initial_hw_address (NMDevice *dev)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (dev);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	priv->initial_hw_addr = g_strdup (nm_device_get_hw_address (dev));
	_LOGD (LOGD_DEVICE | LOGD_VLAN, "read initial MAC address %s", priv->initial_hw_addr);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	/* We assume VLAN interfaces always support carrier detect */
	return NM_DEVICE_CAP_CARRIER_DETECT;
}

static gboolean
bring_up (NMDevice *dev, gboolean *no_firmware)
{
	gboolean success = FALSE;
	guint i = 20;

	while (i-- > 0 && !success) {
		success = NM_DEVICE_CLASS (nm_device_vlan_parent_class)->bring_up (dev, no_firmware);
		g_usleep (50);
	}

	return success;
}

/******************************************************************/

static gboolean
match_parent (NMDeviceVlan *self, const char *parent)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	g_return_val_if_fail (parent != NULL, FALSE);

	if (nm_utils_is_uuid (parent)) {
		NMActRequest *parent_req;
		NMConnection *parent_connection;

		/* If the parent is a UUID, the connection matches if our parent
		 * device has that connection activated.
		 */

		parent_req = nm_device_get_act_request (priv->parent);
		if (!parent_req)
			return FALSE;

		parent_connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (parent_req));
		if (!parent_connection)
			return FALSE;

		if (g_strcmp0 (parent, nm_connection_get_uuid (parent_connection)) != 0)
			return FALSE;
	} else {
		/* interface name */
		if (g_strcmp0 (parent, nm_device_get_ip_iface (priv->parent)) != 0)
			return FALSE;
	}

	return TRUE;
}

static gboolean
match_hwaddr (NMDevice *device, NMConnection *connection, gboolean fail_if_no_hwaddr)
{
	  NMSettingWired *s_wired;
	  const char *setting_mac;
	  const char *device_mac;

	  s_wired = nm_connection_get_setting_wired (connection);
	  if (!s_wired)
		  return !fail_if_no_hwaddr;

	  setting_mac = nm_setting_wired_get_mac_address (s_wired);
	  if (!setting_mac)
		  return !fail_if_no_hwaddr;

	  device_mac = nm_device_get_hw_address (device);

	  return nm_utils_hwaddr_matches (setting_mac, -1, device_mac, -1);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan;
	const char *parent, *iface = NULL;

	if (!NM_DEVICE_CLASS (nm_device_vlan_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan)
		return FALSE;

	if (nm_setting_vlan_get_id (s_vlan) != priv->vlan_id)
		return FALSE;

	/* Check parent interface; could be an interface name or a UUID */
	parent = nm_setting_vlan_get_parent (s_vlan);
	if (parent) {
		if (!match_parent (NM_DEVICE_VLAN (device), parent))
			return FALSE;
	} else {
		/* Parent could be a MAC address in an NMSettingWired */
		if (!match_hwaddr (device, connection, TRUE))
			return FALSE;
	}

	/* Ensure the interface name matches.  If not specified we assume a match
	 * since both the parent interface and the VLAN ID matched by the time we
	 * get here.
	 */
	iface = nm_connection_get_interface_name (connection);
	if (iface) {
		if (g_strcmp0 (nm_device_get_ip_iface (device), iface) != 0)
			return FALSE;
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingVlan *s_vlan;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_VLAN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("VLAN connection"),
	                           NULL,
	                           TRUE);

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'vlan' setting is required.");
		return FALSE;
	}

	/* If there's no VLAN interface, no parent, and no hardware address in the
	 * settings, then there's not enough information to complete the setting.
	 */
	if (   !nm_setting_vlan_get_parent (s_vlan)
	    && !match_hwaddr (device, connection, TRUE)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "The 'vlan' setting had no interface name, parent, or hardware address.");
		return FALSE;
	}

	return TRUE;
}

static void parent_state_changed (NMDevice *parent, NMDeviceState new_state,
                                  NMDeviceState old_state,
                                  NMDeviceStateReason reason,
                                  gpointer user_data);

static void
nm_device_vlan_set_parent (NMDeviceVlan *device, NMDevice *parent)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);

	if (priv->parent_state_id) {
		g_signal_handler_disconnect (priv->parent, priv->parent_state_id);
		priv->parent_state_id = 0;
	}
	g_clear_object (&priv->parent);

	if (parent) {
		priv->parent = g_object_ref (parent);
		priv->parent_state_id = g_signal_connect (priv->parent,
		                                          "state-changed",
		                                          G_CALLBACK (parent_state_changed),
		                                          device);
	}
	g_object_notify (G_OBJECT (device), NM_DEVICE_VLAN_PARENT);
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (device);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (device);
	NMSettingVlan *s_vlan = nm_connection_get_setting_vlan (connection);
	int ifindex = nm_device_get_ifindex (device);
	int parent_ifindex = -1, vlan_id = -1;
	NMDevice *parent;
	const char *setting_parent, *new_parent;

	if (!s_vlan) {
		s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_vlan);
	}

	if (!nm_platform_vlan_get_info (NM_PLATFORM_GET, ifindex, &parent_ifindex, &vlan_id)) {
		_LOGW (LOGD_VLAN, "failed to get VLAN interface info while updating connection.");
		return;
	}

	if (priv->vlan_id != vlan_id) {
		priv->vlan_id = vlan_id;
		g_object_notify (G_OBJECT (device), NM_DEVICE_VLAN_ID);
	}

	if (vlan_id != nm_setting_vlan_get_id (s_vlan))
		g_object_set (s_vlan, NM_SETTING_VLAN_ID, priv->vlan_id, NULL);

	parent = nm_manager_get_device_by_ifindex (nm_manager_get (), parent_ifindex);
	g_assert (parent);
	if (priv->parent != parent)
		nm_device_vlan_set_parent (NM_DEVICE_VLAN (device), parent);

	/* Update parent in the connection; default to parent's interface name */
	new_parent = nm_device_get_iface (parent);
	setting_parent = nm_setting_vlan_get_parent (s_vlan);
	if (setting_parent && nm_utils_is_uuid (setting_parent)) {
		NMConnection *parent_connection;

		/* Don't change a parent specified by UUID if it's still valid */
		parent_connection = nm_connection_provider_get_connection_by_uuid (nm_connection_provider_get (), setting_parent);
		if (parent_connection && nm_device_check_connection_compatible (parent, parent_connection))
			new_parent = NULL;
	}
	if (new_parent)
		g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, new_parent, NULL);
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActRequest *req;
	NMConnection *connection;
	NMSettingVlan *s_vlan;
	NMSettingWired *s_wired;
	const char *cloned_mac;
	NMActStageReturn ret;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_vlan_parent_class)->act_stage1_prepare (dev, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	req = nm_device_get_act_request (dev);
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_connection (req);
	g_return_val_if_fail (connection != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		/* Set device MAC address if the connection wants to change it */
		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
		if (cloned_mac)
			nm_device_set_hw_addr (dev, cloned_mac, "set", LOGD_VLAN);
	}

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (s_vlan) {
		int ifindex = nm_device_get_ifindex (dev);
		int num, i;
		guint32 from, to;

		num = nm_setting_vlan_get_num_priorities (s_vlan, NM_VLAN_INGRESS_MAP);
		for (i = 0; i < num; i++) {
			if (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_INGRESS_MAP, i, &from, &to))
				nm_platform_vlan_set_ingress_map (NM_PLATFORM_GET, ifindex, from, to);
		}
		num = nm_setting_vlan_get_num_priorities (s_vlan, NM_VLAN_EGRESS_MAP);
		for (i = 0; i < num; i++) {
			if (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_EGRESS_MAP, i, &from, &to))
				nm_platform_vlan_set_egress_map (NM_PLATFORM_GET, ifindex, from, to);
		}
	}

	return ret;
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	guint32 mtu;

	connection = nm_device_get_connection (device);
	g_assert (connection);

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		mtu = nm_setting_wired_get_mtu (s_wired);
		if (mtu)
			nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
	}
}

static void
deactivate (NMDevice *device)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (device);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	/* Reset MAC address back to initial address */
	if (priv->initial_hw_addr)
		nm_device_set_hw_addr (device, priv->initial_hw_addr, "reset", LOGD_VLAN);
}

/******************************************************************/

static void
parent_state_changed (NMDevice *parent,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (user_data);

	/* We'll react to our own carrier state notifications. Ignore the parent's. */
	if (reason == NM_DEVICE_STATE_REASON_CARRIER)
		return;

	nm_device_set_unmanaged (NM_DEVICE (self), NM_UNMANAGED_PARENT, !nm_device_get_managed (parent), reason);
}

/******************************************************************/

static void
nm_device_vlan_init (NMDeviceVlan * self)
{
}

static void
constructed (GObject *object)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (object);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);
	int ifindex = nm_device_get_ifindex (NM_DEVICE (self));
	int parent_ifindex = -1, itype;
	int vlan_id;

	if (G_OBJECT_CLASS (nm_device_vlan_parent_class)->constructed)
		G_OBJECT_CLASS (nm_device_vlan_parent_class)->constructed (object);

	if (!priv->parent) {
		_LOGE (LOGD_VLAN, "no parent specified.");
		priv->invalid = TRUE;
		return;
	}

	itype = nm_platform_link_get_type (NM_PLATFORM_GET, ifindex);
	if (itype != NM_LINK_TYPE_VLAN) {
		_LOGE (LOGD_VLAN, "failed to get VLAN interface type.");
		priv->invalid = TRUE;
		return;
	}

	if (!nm_platform_vlan_get_info (NM_PLATFORM_GET, ifindex, &parent_ifindex, &vlan_id)) {
		_LOGW (LOGD_VLAN, "failed to get VLAN interface info.");
		priv->invalid = TRUE;
		return;
	}

	if (   parent_ifindex < 0
	    || parent_ifindex != nm_device_get_ip_ifindex (priv->parent)
	    || vlan_id < 0) {
		_LOGW (LOGD_VLAN, "VLAN parent ifindex (%d) or VLAN ID (%d) invalid.",
		       parent_ifindex, priv->vlan_id);
		priv->invalid = TRUE;
		return;
	}

	priv->vlan_id = vlan_id;
	_LOGI (LOGD_HW | LOGD_VLAN, "VLAN ID %d with parent %s",
	       priv->vlan_id, nm_device_get_iface (priv->parent));
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_boxed (value, priv->parent ? nm_device_get_path (priv->parent) : "/");
		break;
	case PROP_INT_PARENT_DEVICE:
		g_value_set_object (value, priv->parent);
		break;
	case PROP_VLAN_ID:
		g_value_set_uint (value, priv->vlan_id);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_INT_PARENT_DEVICE:
		nm_device_vlan_set_parent (NM_DEVICE_VLAN (object), g_value_get_object (value));
		break;
	case PROP_VLAN_ID:
		priv->vlan_id = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (object);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_vlan_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	nm_device_vlan_set_parent (self, NULL);

	G_OBJECT_CLASS (nm_device_vlan_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceVlan *self = NM_DEVICE_VLAN (object);
	NMDeviceVlanPrivate *priv = NM_DEVICE_VLAN_GET_PRIVATE (self);

	g_free (priv->initial_hw_addr);

	G_OBJECT_CLASS (nm_device_vlan_parent_class)->finalize (object);
}

static void
nm_device_vlan_class_init (NMDeviceVlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	parent_class->connection_type = NM_SETTING_VLAN_SETTING_NAME;

	g_type_class_add_private (object_class, sizeof (NMDeviceVlanPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	parent_class->update_initial_hw_address = update_initial_hw_address;
	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->bring_up = bring_up;
	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;
	parent_class->deactivate = deactivate;

	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;
	parent_class->update_connection = update_connection;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_boxed (NM_DEVICE_VLAN_PARENT, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
	g_object_class_install_property
		(object_class, PROP_VLAN_ID,
		 g_param_spec_uint (NM_DEVICE_VLAN_ID, "", "",
		                    0, 4095, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	/* Internal properties */
	g_object_class_install_property
	    (object_class, PROP_INT_PARENT_DEVICE,
	     g_param_spec_object (NM_DEVICE_VLAN_INT_PARENT_DEVICE, "", "",
	                          NM_TYPE_DEVICE,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_vlan_object_info);
}

/*************************************************************/

#define NM_TYPE_VLAN_FACTORY (nm_vlan_factory_get_type ())
#define NM_VLAN_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VLAN_FACTORY, NMVlanFactory))

static NMDevice *
new_link (NMDeviceFactory *factory, NMPlatformLink *plink, GError **error)
{
	int parent_ifindex = -1;
	NMDevice *parent, *device;

	if (plink->type != NM_LINK_TYPE_VLAN)
		return NULL;

	/* Have to find the parent device */
	if (!nm_platform_vlan_get_info (NM_PLATFORM_GET, plink->ifindex, &parent_ifindex, NULL)) {
		nm_log_err (LOGD_HW, "(%s): failed to get VLAN parent ifindex", plink->name);
		return NULL;
	}

	parent = nm_manager_get_device_by_ifindex (nm_manager_get (), parent_ifindex);
	if (!parent) {
		/* If udev signaled the VLAN interface before it signaled
		 * the VLAN's parent at startup we may not know about the
		 * parent device yet.  But we'll find it on the second pass
		 * from nm_manager_start().
		 */
		nm_log_dbg (LOGD_HW, "(%s): VLAN parent interface unknown", plink->name);
		return NULL;
	}

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_VLAN,
	                                    NM_DEVICE_PLATFORM_DEVICE, plink,
	                                    NM_DEVICE_VLAN_INT_PARENT_DEVICE, parent,
	                                    NM_DEVICE_DRIVER, "8021q",
	                                    NM_DEVICE_TYPE_DESC, "VLAN",
	                                    NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_VLAN,
	                                    NULL);
	if (NM_DEVICE_VLAN_GET_PRIVATE (device)->invalid) {
		g_object_unref (device);
		device = NULL;
	}

	/* Set initial parent-dependent unmanaged flag */
	if (device)
		nm_device_set_initial_unmanaged_flag (device, NM_UNMANAGED_PARENT, !nm_device_get_managed (parent));

	return device;
}

static NMDevice *
create_virtual_device_for_connection (NMDeviceFactory *factory,
                                      NMConnection *connection,
                                      NMDevice *parent,
                                      GError **error)
{
	NMDevice *device;
	NMSettingVlan *s_vlan;
	char *iface;

	if (!nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME))
		return NULL;

	g_return_val_if_fail (NM_IS_DEVICE (parent), NULL);

	s_vlan = nm_connection_get_setting_vlan (connection);
	g_return_val_if_fail (s_vlan != NULL, NULL);

	iface = g_strdup (nm_connection_get_interface_name (connection));
	if (!iface) {
		iface = nm_utils_new_vlan_name (nm_device_get_ip_iface (parent),
		                                nm_setting_vlan_get_id (s_vlan));
	}

	if (   !nm_platform_vlan_add (NM_PLATFORM_GET,
	                              iface,
	                              nm_device_get_ifindex (parent),
	                              nm_setting_vlan_get_id (s_vlan),
	                              nm_setting_vlan_get_flags (s_vlan))
	    && nm_platform_get_error (NM_PLATFORM_GET) != NM_PLATFORM_ERROR_EXISTS) {
		nm_log_warn (LOGD_DEVICE | LOGD_VLAN, "(%s) failed to add VLAN interface for '%s'",
		             iface, nm_connection_get_id (connection));
		g_free (iface);
		return NULL;
	}

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_VLAN,
	                                    NM_DEVICE_IFACE, iface,
	                                    NM_DEVICE_VLAN_INT_PARENT_DEVICE, parent,
	                                    NM_DEVICE_DRIVER, "8021q",
	                                    NM_DEVICE_TYPE_DESC, "VLAN",
	                                    NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_VLAN,
	                                    NULL);
	g_free (iface);
	if (NM_DEVICE_VLAN_GET_PRIVATE (device)->invalid) {
		g_object_unref (device);
		device = NULL;
	}

	/* Set initial parent-dependent unmanaged flag */
	if (device)
		nm_device_set_initial_unmanaged_flag (device, NM_UNMANAGED_PARENT, !nm_device_get_managed (parent));

	return device;
}

DEFINE_DEVICE_FACTORY_INTERNAL(VLAN, Vlan, vlan, \
	factory_iface->new_link = new_link; \
	factory_iface->create_virtual_device_for_connection = create_virtual_device_for_connection;
	)


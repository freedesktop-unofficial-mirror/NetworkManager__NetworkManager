/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_PLATFORM_UTILS_H__
#define __NM_PLATFORM_UTILS_H__

#include "config.h"

#include "nm-platform.h"
#include "nm-multi-index.h"
#include "nm-utils-internal.h"

#include <netlink/object.h>
#include <gudev/gudev.h>


typedef enum { /*< skip >*/
	OBJECT_TYPE_UNKNOWN,
	OBJECT_TYPE_LINK,
	OBJECT_TYPE_IP4_ADDRESS,
	OBJECT_TYPE_IP6_ADDRESS,
	OBJECT_TYPE_IP4_ROUTE,
	OBJECT_TYPE_IP6_ROUTE,
	__OBJECT_TYPE_LAST,
	OBJECT_TYPE_MAX = __OBJECT_TYPE_LAST - 1,
} ObjectType;

typedef struct NMPObject NMPObject;

typedef enum { /*< skip >*/
	NMP_CACHE_OPS_UNCHANGED       = NM_PLATFORM_SIGNAL_NONE,
	NMP_CACHE_OPS_UPDATED         = NM_PLATFORM_SIGNAL_CHANGED,
	NMP_CACHE_OPS_ADDED           = NM_PLATFORM_SIGNAL_ADDED,
	NMP_CACHE_OPS_REMOVED         = NM_PLATFORM_SIGNAL_REMOVED,
} NMPCacheOpsType;

typedef enum { /*< skip >*/
	NMP_OBJECT_ASPECT_NONE                  = 0,
	NMP_OBJECT_ASPECT_PUBLIC                = (1LL << 1),
	NMP_OBJECT_ASPECT_NETLINK               = (1LL << 2),
	NMP_OBJECT_ASPECT_UDEV                  = (1LL << 3),

	__NMP_OBJECT_ASPECT_LAST,
	NMP_OBJECT_ASPECT_ALL                   = ((__NMP_OBJECT_ASPECT_LAST - 1) << 1) - 1,
} NMPObjectAspects;

typedef enum { /*< skip >*/
	NMP_CACHE_ID_TYPE_LINKS_ALL,
	NMP_CACHE_ID_TYPE_LINKS_VISIBLE_ONLY,

	NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX,

	/* three indeces for the visibile routes. */
	NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ALL,
	NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT,
	NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT,

	__NMP_CACHE_ID_TYPE_MAX,
	NMP_CACHE_ID_TYPE_MAX = __NMP_CACHE_ID_TYPE_MAX - 1,
} NMPCacheIdType;

typedef struct {
	union {
		NMMultiIndexId base;
		guint8 _id_type; /* NMPCacheIdType as guint8 */
		struct {
			/* NMP_CACHE_ID_TYPE_LINKS_ALL */
			/* NMP_CACHE_ID_TYPE_LINKS_VISIBLE_ONLY */
			guint8 _id_type;

			/* the @global_id is only defined by it's type. For example,
			 * there is only one cache-id for NMP_CACHE_ID_TYPE_LINKS_ALL,
			 * namly the one with _id_type set to NMP_CACHE_ID_TYPE_LINKS_ALL. */
		} global_id;
		struct {
			/* NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX */
			guint8 _id_type;
			guint8 obj_type; /* ObjectType as guint8 */
			int ifindex;
		} addrroute_by_ifindex;
		struct {
			/* NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ALL */
			/* NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT */
			/* NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT */
			guint8 _id_type;
			guint8 is_v4;
			int ifindex;
		} routes_visible;
	};
} NMPCacheId;

typedef struct {
	ObjectType type;
	int sizeof_data;
	int sizeof_public;
	gboolean has_other_aspects;
	const char *nl_type;
	const char *signal_type;

	/* returns %FALSE, if the obj type would never have an entry for index type @id_type. If @obj has an index,
	 * initialize @id and set @out_id to it. Otherwise, @out_id is NULL. */
	gboolean (*cmd_obj_init_cache_id) (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id);

	gboolean (*cmd_obj_equal) (const NMPObject *obj1, const NMPObject *obj2, NMPObjectAspects obj_aspect);
	void (*cmd_obj_copy) (NMPObject *dst, const NMPObject *src, NMPObjectAspects obj_aspect);
	void (*cmd_obj_stackinit_id) (NMPObject *obj, const NMPObject *src);
	void (*cmd_obj_dispose) (NMPObject *obj);
	gboolean (*cmd_obj_is_alive) (const NMPObject *obj);
	gboolean (*cmd_obj_is_visible) (const NMPObject *obj);

	/* functions that operate on NMPlatformObject */
	gboolean (*cmd_plobj_init_from_nl) (NMPlatformObject *obj, const struct nl_object *nlo, gboolean id_only);
	struct nl_object *(*cmd_plobj_to_nl) (NMPlatform *platform, const NMPlatformObject *obj, gboolean id_only);
	void (*cmd_plobj_id_copy) (NMPlatformObject *dst, const NMPlatformObject *src);
	gboolean (*cmd_plobj_id_equal) (const NMPlatformObject *obj1, const NMPlatformObject *obj2);
	guint (*cmd_plobj_id_hash) (const NMPlatformObject *obj);
	const char *(*cmd_plobj_to_string) (const NMPlatformObject *obj);
	int (*cmd_plobj_cmp) (const NMPlatformObject *obj1, const NMPlatformObject *obj2);
} NMPClass;

typedef struct {
	NMPlatformLink _public;

	struct {
		guint8 is_in_netlink;

		/* this is the "native" up flag as reported by netlink. For bridges and bonds without
		 * slaves, IFF_LOWER_UP is set. We coerce this value to expose a "real-connected" value in
		 * self->_public.connected . */
		guint8 connected_native;

		/* Whether the link type is "UNKNOWN" due to failed detection via udev. */
		guint8 link_type_unknown_udev;

		int arptype;

		const char *rtnl_link_type;
	} netlink;

	struct {
		GUdevDevice *device;
	} udev;
} NMPObjectLink;

typedef struct {
	NMPlatformIP4Address _public;
} NMPObjectIP4Address;

typedef struct {
	NMPlatformIP4Route _public;
} NMPObjectIP4Route;

typedef struct {
	NMPlatformIP6Address _public;
} NMPObjectIP6Address;

typedef struct {
	NMPlatformIP6Route _public;
} NMPObjectIP6Route;

struct NMPObject {
	const NMPClass *_class;
	int _ref_count;
	guint8 is_cached;
	union {
		NMPlatformObject        object;

		NMPlatformLink          link;
		NMPObjectLink           _link;

		NMPlatformIPAddress     ip_address;
		NMPlatformIPXAddress    ipx_address;
		NMPlatformIP4Address    ip4_address;
		NMPlatformIP6Address    ip6_address;
		NMPObjectIP4Address     _ip4_address;
		NMPObjectIP6Address     _ip6_address;

		NMPlatformIPRoute       ip_route;
		NMPlatformIPXRoute      ipx_route;
		NMPlatformIP4Route      ip4_route;
		NMPlatformIP6Route      ip6_route;
		NMPObjectIP4Route       _ip4_route;
		NMPObjectIP6Route       _ip6_route;
	};
};

#define NMP_REF_COUNT_INITSTACK (G_MAXINT)

#define NMP_OBJECT_UP_CAST(plobj) ({ \
    const NMPlatformObject *const _plobj = (plobj); \
    (_plobj ? (NMPObject *) ( &(((char *) _plobj)[-((int) G_STRUCT_OFFSET (NMPObject, object))]) ) : NULL); \
})

/* Check if @obj is non-NULL. */ \
#define NMP_OBJECT_IS_VALID(obj) ({ \
    const NMPObject *const _obj = (obj); \
    (_obj && _obj->_ref_count > 0); \
})

#define NMP_OBJECT_IS_STACKINIT(obj) ({ \
    const NMPObject *const _obj = (obj); \
    (_obj && _obj->_ref_count == NMP_REF_COUNT_INITSTACK); \
})

#define NMP_OBJECT_GET_CLASS(obj) ({ \
    const NMPObject *const _obj = (obj); \
    nm_assert (_obj && _obj->_ref_count > 0 && _obj->_class); \
    _obj->_class; \
})

#define NMP_OBJECT_GET_TYPE(obj) ({ \
    const NMPObject *const _obj = (obj); \
    nm_assert (!_obj || (_obj->_ref_count > 0 && _obj->_class)); \
    (_obj ? _obj->_class->type : OBJECT_TYPE_UNKNOWN); \
})

typedef struct _NMPCache NMPCache;


const NMPClass *nmp_class_from_type (ObjectType type);

NMPObject *nmp_object_get (NMPObject *object);
void nmp_object_put (NMPObject *object);
NMPObject *nmp_object_new (ObjectType type, const NMPlatformObject *plob);

const NMPObject *nmp_object_stackinit (NMPObject *obj, ObjectType type, const NMPlatformObject *plobj);
const NMPObject *nmp_object_stackinit_id  (NMPObject *obj, const NMPObject *src);
const NMPObject *nmp_object_stackinit_id_link (NMPObject *obj, int ifindex);
const NMPObject *nmp_object_stackinit_id_ip4_address (NMPObject *obj, int ifindex, guint32 address, int plen);
const NMPObject *nmp_object_stackinit_id_ip6_address (NMPObject *obj, int ifindex, const struct in6_addr *address, int plen);
const NMPObject *nmp_object_stackinit_id_ip4_route (NMPObject *obj, int ifindex, guint32 network, int plen, guint32 metric);
const NMPObject *nmp_object_stackinit_id_ip6_route (NMPObject *obj, int ifindex, const struct in6_addr *network, int plen, guint32 metric);

const char *nmp_object_to_string (const NMPObject *obj);
int nmp_object_cmp (const NMPObject *obj1, const NMPObject *obj2);
gboolean nmp_object_equal (const NMPObject *obj1, const NMPObject *obj2, NMPObjectAspects obj_aspect);
void nmp_object_copy (NMPObject *dst, const NMPObject *src, NMPObjectAspects obj_aspect);
NMPObject *nmp_object_clone (const NMPObject *obj, gboolean id_only);
gboolean nmp_object_id_equal (const NMPObject *obj1, const NMPObject *obj2);
guint nmp_object_id_hash (const NMPObject *obj);
gboolean nmp_object_is_alive (const NMPObject *obj);
gboolean nmp_object_is_visible (const NMPObject *obj);

#define auto_nmp_obj __attribute__((cleanup(_nmp_auto_obj_cleanup)))
static inline void
_nmp_auto_obj_cleanup (NMPObject **pobj)
{
	nmp_object_put (*pobj);
}

gboolean nmp_cache_id_equal (const NMPCacheId *a, const NMPCacheId *b);
guint nmp_cache_id_hash (const NMPCacheId *id);
NMPCacheId *nmp_cache_id_clone (const NMPCacheId *id);
void nmp_cache_id_destroy (NMPCacheId *id);

NMPCacheId *nmp_cache_id_init (NMPCacheId *id, NMPCacheIdType id_type);
NMPCacheId *nmp_cache_id_init_links (NMPCacheId *id, gboolean visible_only);
NMPCacheId *nmp_cache_id_init_addrroute_by_ifindex (NMPCacheId *id, ObjectType obj_type, int ifindex);
NMPCacheId *nmp_cache_id_init_routes_visible (NMPCacheId *id, NMPCacheIdType id_type, gboolean is_v4, int ifindex);

const NMPlatformObject *const *nmp_cache_lookup_multi (const NMPCache *cache, const NMPCacheId *cache_id, guint *out_len);
GArray *nmp_cache_lookup_multi_to_array (const NMPCache *cache, ObjectType obj_type, const NMPCacheId *cache_id);
const NMPObject *nmp_cache_lookup_obj (const NMPCache *cache, const NMPObject *obj);
const NMPObject *nmp_cache_lookup_link (const NMPCache *cache, int ifindex);
const NMPlatformLink *nmp_cache_lookup_link_downcast (const NMPCache *cache, int ifindex);

NMPCacheOpsType nmp_cache_remove (NMPCache *cache, const NMPObject *obj, NMPObject **out_obj, gboolean *out_was_visible);
NMPCacheOpsType nmp_cache_update (NMPCache *cache, NMPObject *obj, NMPObjectAspects obj_aspect, NMPObject **out_obj, gboolean *out_was_visible);

NMPCache *nmp_cache_new (void);
void nmp_cache_free (NMPCache *cache);

NMPObject *nmp_object_from_nl (const struct nl_object *nlo, gboolean id_only);
struct nl_object *nmp_object_to_nl (NMPlatform *platform, const NMPObject *obj, gboolean id_only);

/* the following functions are currently implemented inside nm-linux-platform, because
 * they depend on utility functions there. */
ObjectType _nlo_get_object_type (const struct nl_object *nlo);
gboolean _nmp_vt_cmd_plobj_init_from_nl_link (NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip4_address (NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip6_address (NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip4_route (NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only);
gboolean _nmp_vt_cmd_plobj_init_from_nl_ip6_route (NMPlatformObject *_obj, const struct nl_object *_nlo, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_link (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip4_address (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip6_address (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip4_route (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);
struct nl_object *_nmp_vt_cmd_plobj_to_nl_ip6_route (NMPlatform *platform, const NMPlatformObject *_obj, gboolean id_only);

#endif /* __NM_PLATFORM_UTILS_H__ */

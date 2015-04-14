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

#include "nmp-object.h"

#include "NetworkManagerUtils.h"

struct _NMPCache {
	/* the cache contains only one hash table for all object types, and similarly
	 * it contains only one NMMultiIndex.
	 * This works, because different object types don't ever compare equal and
	 * because their index ids also don't overlap.
	 *
	 * For routes and addresses, the cache contains an address if (and only if) the
	 * object was reported via netlink.
	 * For links, the cache contain a link if it was reported by either netlink
	 * or udev. That means, a link object can be alive, even if it was already
	 * removed via netlink.
	 *
	 * This effectively merges the udev-device cache into the NMPCache.
	 */

	GHashTable *idx_main;
	NMMultiIndex *idx_multi;
};

static const NMPClass nmp_classes[];

/******************************************************************/

static inline guint
_id_hash_ip6_addr (const struct in6_addr *addr)
{
	guint hash = 5381;
	int i;

	for (i = 0; i < sizeof (*addr); i++)
		hash = (hash * 33) + ((const guint8 *) addr)[i];
	hash ^= (guint) addr->s6_addr32[0];
	hash ^= (guint) addr->s6_addr32[1];
	hash ^= (guint) addr->s6_addr32[2];
	hash ^= (guint) addr->s6_addr32[3];
	return hash;
}

/******************************************************************/

const NMPClass *
nmp_class_from_type (ObjectType type)
{
	g_return_val_if_fail (type > OBJECT_TYPE_UNKNOWN && type <= OBJECT_TYPE_MAX, NULL);

	return &nmp_classes[type - 1];
}

/******************************************************************/

NMPObject *
nmp_object_get (NMPObject *object)
{
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (object), NULL);
	g_return_val_if_fail (object->_ref_count != NMP_REF_COUNT_INITSTACK, NULL);
	object->_ref_count++;

	return object;
}

void
nmp_object_put (NMPObject *object)
{
	if (object) {
		g_return_if_fail (object->_ref_count > 0);
		g_return_if_fail (object->_ref_count != NMP_REF_COUNT_INITSTACK);
		if (--object->_ref_count <= 0) {
			const NMPClass *klass = NMP_OBJECT_GET_CLASS (object);

			nm_assert (!object->is_cached);
			if (klass->cmd_obj_dispose)
				klass->cmd_obj_dispose (object);
			g_slice_free1 (klass->sizeof_data + G_STRUCT_OFFSET (NMPObject, object), object);
		}
	}
}

static void
_vt_cmd_obj_dispose_link (NMPObject *obj)
{
	g_clear_object (&obj->_link.udev.device);
}

static NMPObject *
_nmp_object_new_from_class (const NMPClass *klass)
{
	NMPObject *obj;

	nm_assert (klass);
	nm_assert (klass->sizeof_data > 0);
	nm_assert (klass->sizeof_public > 0 && klass->sizeof_public <= klass->sizeof_data);

	obj = g_slice_alloc0 (klass->sizeof_data + G_STRUCT_OFFSET (NMPObject, object));
	obj->_class = klass;
	obj->_ref_count = 1;
	return obj;
}

NMPObject *
nmp_object_new (ObjectType type, const NMPlatformObject *plobj)
{
	const NMPClass *klass = nmp_class_from_type (type);
	NMPObject *obj;

	obj = _nmp_object_new_from_class (klass);
	if (plobj)
		memcpy (&obj->object, plobj, klass->sizeof_public);
	return obj;
}

/******************************************************************/

static const NMPObject *
_nmp_object_stackinit_from_class (NMPObject *obj, const NMPClass *klass)
{
	nm_assert (klass);

	memset (obj, 0, sizeof (NMPObject));
	obj->_class = klass;
	obj->_ref_count = NMP_REF_COUNT_INITSTACK;
	return obj;
}

const NMPObject *
nmp_object_stackinit (NMPObject *obj, ObjectType type, const NMPlatformObject *plobj)
{
	const NMPClass *klass = nmp_class_from_type (type);

	_nmp_object_stackinit_from_class (obj, klass);
	if (plobj)
		memcpy (&obj->object, plobj, klass->sizeof_public);
	return obj;
}

const NMPObject *
nmp_object_stackinit_id  (NMPObject *obj, const NMPObject *src)
{
	nm_assert (NMP_OBJECT_IS_VALID (src));
	nm_assert (obj);

	NMP_OBJECT_GET_CLASS (src)->cmd_obj_stackinit_id (obj, src);
	return obj;
}

const NMPObject *
nmp_object_stackinit_id_link (NMPObject *obj, int ifindex)
{
	nmp_object_stackinit (obj, OBJECT_TYPE_LINK, NULL);
	obj->link.ifindex = ifindex;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_link (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_link (obj, src->link.ifindex);
}

const NMPObject *
nmp_object_stackinit_id_ip4_address (NMPObject *obj, int ifindex, guint32 address, int plen)
{
	nmp_object_stackinit (obj, OBJECT_TYPE_IP4_ADDRESS, NULL);
	obj->ip4_address.ifindex = ifindex;
	obj->ip4_address.address = address;
	obj->ip4_address.plen = plen;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip4_address (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip4_address (obj, src->ip_address.ifindex, src->ip4_address.address, src->ip_address.plen);
}

const NMPObject *
nmp_object_stackinit_id_ip6_address (NMPObject *obj, int ifindex, const struct in6_addr *address, int plen)
{
	nmp_object_stackinit (obj, OBJECT_TYPE_IP6_ADDRESS, NULL);
	obj->ip4_address.ifindex = ifindex;
	if (address)
		obj->ip6_address.address = *address;
	obj->ip6_address.plen = plen;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip6_address (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip6_address (obj, src->ip_address.ifindex, &src->ip6_address.address, src->ip_address.plen);
}

const NMPObject *
nmp_object_stackinit_id_ip4_route (NMPObject *obj, int ifindex, guint32 network, int plen, guint32 metric)
{
	nmp_object_stackinit (obj, OBJECT_TYPE_IP4_ROUTE, NULL);
	obj->ip4_route.ifindex = ifindex;
	obj->ip4_route.network = network;
	obj->ip4_route.plen = plen;
	obj->ip4_route.metric = metric;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip4_route (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip4_route (obj, src->ip_route.ifindex, src->ip4_route.network, src->ip_route.plen, src->ip_route.metric);
}

const NMPObject *
nmp_object_stackinit_id_ip6_route (NMPObject *obj, int ifindex, const struct in6_addr *network, int plen, guint32 metric)
{
	nmp_object_stackinit (obj, OBJECT_TYPE_IP6_ROUTE, NULL);
	obj->ip6_route.ifindex = ifindex;
	if (network)
		obj->ip6_route.network = *network;
	obj->ip6_route.plen = plen;
	obj->ip6_route.metric = metric;
	return obj;
}

static void
_vt_cmd_obj_stackinit_id_ip6_route (NMPObject *obj, const NMPObject *src)
{
	nmp_object_stackinit_id_ip6_route (obj, src->ip_route.ifindex, &src->ip6_route.network, src->ip_route.plen, src->ip_route.metric);
}

/******************************************************************/

const char *
nmp_object_to_string (const NMPObject *obj)
{
	if (!obj)
		return "NULL";

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);
	return NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_string (&obj->object);
}

int
nmp_object_cmp (const NMPObject *obj1, const NMPObject *obj2)
{
	if (obj1 == obj2)
		return 0;
	if (!obj1)
		return -1;
	if (!obj2)
		return 1;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj1), -1);
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj2), 1);

	if (NMP_OBJECT_GET_CLASS (obj1) != NMP_OBJECT_GET_CLASS (obj2))
		return NMP_OBJECT_GET_CLASS (obj1) < NMP_OBJECT_GET_CLASS (obj2) ? -1 : 1;

	return NMP_OBJECT_GET_CLASS (obj1)->cmd_plobj_cmp (&obj1->object, &obj2->object);
}

gboolean
nmp_object_equal (const NMPObject *obj1, const NMPObject *obj2, NMPObjectAspects obj_aspect)
{
	const NMPClass *klass;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj1), FALSE);
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj2), FALSE);

	if (obj1 == obj2)
		return TRUE;

	klass = NMP_OBJECT_GET_CLASS (obj1);

	if (klass != NMP_OBJECT_GET_CLASS (obj2))
		return FALSE;

	return klass->cmd_obj_equal (obj1, obj2, obj_aspect);
}

static gboolean
_vt_cmd_obj_equal_plain (const NMPObject *obj1, const NMPObject *obj2, NMPObjectAspects obj_aspect)
{
	const NMPClass *klass = NMP_OBJECT_GET_CLASS (obj1);

	if (NM_FLAGS_ANY (obj_aspect, NMP_OBJECT_ASPECT_PUBLIC | NMP_OBJECT_ASPECT_NETLINK))
		return klass->cmd_plobj_cmp (&obj1->object, &obj2->object) == 0;
	return klass->cmd_plobj_id_equal (&obj1->object, &obj2->object);
}

static gboolean
_vt_cmd_obj_equal_link (const NMPObject *obj1, const NMPObject *obj2, NMPObjectAspects obj_aspect)
{
	const NMPClass *klass = NMP_OBJECT_GET_CLASS (obj1);

	if (!klass->cmd_plobj_id_equal (&obj1->object, &obj2->object))
		return FALSE;

	if (NM_FLAGS_ANY (obj_aspect, NMP_OBJECT_ASPECT_PUBLIC)) {
		if (klass->cmd_plobj_cmp (&obj1->object, &obj2->object) != 0)
			return FALSE;
	}

	if (NM_FLAGS_HAS (obj_aspect, NMP_OBJECT_ASPECT_NETLINK)) {
		if (   (obj1->_link.netlink.is_in_netlink != obj2->_link.netlink.is_in_netlink)
		    || (obj1->_link.netlink.connected_native != obj2->_link.netlink.connected_native)
		    || (obj1->_link.netlink.link_type_unknown_udev != obj2->_link.netlink.link_type_unknown_udev)
		    || (obj1->_link.netlink.arptype != obj2->_link.netlink.arptype)
		    || (obj1->_link.netlink.rtnl_link_type != obj2->_link.netlink.rtnl_link_type))
			return FALSE;
	}

	if (NM_FLAGS_HAS (obj_aspect, NMP_OBJECT_ASPECT_UDEV)) {
		if (obj1->_link.udev.device != obj2->_link.udev.device)
			return FALSE;
	}
	return TRUE;
}

/* @src is a const object, which is not entirely correct for link types, where
 * we increase the ref count for src->_link.udev.device.
 * Hence, nmp_object_copy() can violate the const promise of @src.
 * */
void
nmp_object_copy (NMPObject *dst, const NMPObject *src, NMPObjectAspects obj_aspect)
{
	g_return_if_fail (NMP_OBJECT_IS_VALID (dst));
	g_return_if_fail (NMP_OBJECT_IS_VALID (src));
	g_return_if_fail (!NMP_OBJECT_IS_STACKINIT (dst));

	if (src != dst) {
		const NMPClass *klass = NMP_OBJECT_GET_CLASS (dst);

		g_return_if_fail (klass == NMP_OBJECT_GET_CLASS (src));

		klass->cmd_obj_copy (dst, src, obj_aspect);
	}
}

#define _vt_cmd_plobj_id_copy(type, plat_type, cmd) \
static void \
_vt_cmd_plobj_id_copy_##type (NMPlatformObject *_dst, const NMPlatformObject *_src) \
{ \
	plat_type *const dst = (plat_type *) _dst; \
	const plat_type *const src = (const plat_type *) _src; \
	{ cmd } \
}
_vt_cmd_plobj_id_copy (link, NMPlatformLink, {
	dst->ifindex = src->ifindex;
});
_vt_cmd_plobj_id_copy (ip4_address, NMPlatformIP4Address, {
	dst->ifindex = src->ifindex;
	dst->plen = src->plen;
	dst->address = src->address;
});
_vt_cmd_plobj_id_copy (ip6_address, NMPlatformIP6Address, {
	dst->ifindex = src->ifindex;
	dst->plen = src->plen;
	dst->address = src->address;
});
_vt_cmd_plobj_id_copy (ip4_route, NMPlatformIP4Route, {
	dst->ifindex = src->ifindex;
	dst->plen = src->plen;
	dst->metric = src->metric;
	dst->network = src->network;
});
_vt_cmd_plobj_id_copy (ip6_route, NMPlatformIP6Route, {
	dst->ifindex = src->ifindex;
	dst->plen = src->plen;
	dst->metric = src->metric;
	dst->network = src->network;
});

static void
_vt_cmd_obj_copy_plain (NMPObject *dst, const NMPObject *src, NMPObjectAspects obj_aspect)
{
	if (NM_FLAGS_ANY (obj_aspect, NMP_OBJECT_ASPECT_PUBLIC | NMP_OBJECT_ASPECT_NETLINK))
		memcpy (&dst->object, &src->object, NMP_OBJECT_GET_CLASS (dst)->sizeof_public);
	else
		NMP_OBJECT_GET_CLASS (dst)->cmd_plobj_id_copy (&dst->object, &src->object);
}

static void
_vt_cmd_obj_copy_link (NMPObject *dst, const NMPObject *src, NMPObjectAspects obj_aspect)
{
	if (NM_FLAGS_ANY (obj_aspect, NMP_OBJECT_ASPECT_PUBLIC))
		dst->link = src->link;
	else
		_vt_cmd_plobj_id_copy_link (&dst->object, &src->object);

	if (NM_FLAGS_HAS (obj_aspect, NMP_OBJECT_ASPECT_NETLINK))
		dst->_link.netlink = src->_link.netlink;

	if (NM_FLAGS_HAS (obj_aspect, NMP_OBJECT_ASPECT_UDEV)) {
		if (src->_link.udev.device != dst->_link.udev.device) {
			g_clear_object (&dst->_link.udev.device);
			if (src->_link.udev.device) {
				/* we cheat here and increase the ref-count of device on the const @src.
				 * Otherwise, nmp_object_clone() and nmp_object_copy() don't accept
				 * const @src arguments, which is annoying too. */
				dst->_link.udev.device = g_object_ref (src->_link.udev.device);
			}
		}
	}
}

/* @src similar to nmp_object_copy(), we violate the const promise of
 * @obj.
 * */
NMPObject *
nmp_object_clone (const NMPObject *obj, gboolean id_only)
{
	NMPObject *dst;

	if (!obj)
		return NULL;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), NULL);

	dst = _nmp_object_new_from_class (NMP_OBJECT_GET_CLASS (obj));
	nmp_object_copy (dst, obj, id_only ? NMP_OBJECT_ASPECT_NONE : NMP_OBJECT_ASPECT_ALL);
	return dst;
}

gboolean
nmp_object_id_equal (const NMPObject *obj1, const NMPObject *obj2)
{
	if (obj1 == obj2)
		return TRUE;
	if (!obj1 || !obj2)
		return FALSE;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj1), FALSE);
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj2), FALSE);

	if (NMP_OBJECT_GET_CLASS (obj1) != NMP_OBJECT_GET_CLASS (obj2))
		return FALSE;

	return NMP_OBJECT_GET_CLASS (obj1)->cmd_plobj_id_equal (&obj1->object, &obj2->object);
}

#define _vt_cmd_plobj_id_equal(type, plat_type, cmd) \
static gboolean \
_vt_cmd_plobj_id_equal_##type (const NMPlatformObject *_obj1, const NMPlatformObject *_obj2) \
{ \
	const plat_type *const obj1 = (const plat_type *) _obj1; \
	const plat_type *const obj2 = (const plat_type *) _obj2; \
	return (cmd); \
}
_vt_cmd_plobj_id_equal (link, NMPlatformLink,
                            obj1->ifindex == obj2->ifindex);
_vt_cmd_plobj_id_equal (ip4_address, NMPlatformIP4Address,
                            obj1->ifindex == obj2->ifindex
                         && obj1->plen == obj2->plen
                         && obj1->address == obj2->address);
_vt_cmd_plobj_id_equal (ip6_address, NMPlatformIP6Address,
                            obj1->ifindex == obj2->ifindex
                         && obj1->plen == obj2->plen
                         && IN6_ARE_ADDR_EQUAL (&obj1->address, &obj2->address));
_vt_cmd_plobj_id_equal (ip4_route, NMPlatformIP4Route,
                            obj1->ifindex == obj2->ifindex
                         && obj1->plen == obj2->plen
                         && obj1->metric == obj2->metric
                         && obj1->network == obj2->network);
_vt_cmd_plobj_id_equal (ip6_route, NMPlatformIP6Route,
                            obj1->ifindex == obj2->ifindex
                         && obj1->plen == obj2->plen
                         && obj1->metric == obj2->metric
                         && IN6_ARE_ADDR_EQUAL( &obj1->network, &obj2->network));

guint
nmp_object_id_hash (const NMPObject *obj)
{
	if (!obj)
		return 0;

	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), 0);
	return NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_id_hash (&obj->object);
}

#define _vt_cmd_plobj_id_hash(type, plat_type, cmd) \
static guint \
_vt_cmd_plobj_id_hash_##type (const NMPlatformObject *_obj) \
{ \
	const plat_type *const obj = (const plat_type *) _obj; \
	guint hash; \
	{ cmd; } \
	return hash; \
}
_vt_cmd_plobj_id_hash (link, NMPlatformLink, {
	/* libnl considers:
	 *   .oo_id_attrs = LINK_ATTR_IFINDEX | LINK_ATTR_FAMILY,
	 */
	hash = (guint) 3982791431;
	hash = hash      + ((guint) obj->ifindex);
})
_vt_cmd_plobj_id_hash (ip4_address, NMPlatformIP4Address, {
	/* libnl considers:
	 *   .oo_id_attrs = (ADDR_ATTR_FAMILY | ADDR_ATTR_IFINDEX |
	 *                   ADDR_ATTR_LOCAL | ADDR_ATTR_PREFIXLEN),
	 */
	hash = (guint) 3591309853;
	hash = hash      + ((guint) obj->ifindex);
	hash = hash * 33 + ((guint) obj->plen);
	hash = hash * 33 + ((guint) obj->address);
})
_vt_cmd_plobj_id_hash (ip6_address, NMPlatformIP6Address, {
	hash = (guint) 2907861637;
	hash = hash      + ((guint) obj->ifindex);
	hash = hash * 33 + ((guint) obj->plen);
	hash = hash * 33 + _id_hash_ip6_addr (&obj->address);
})
_vt_cmd_plobj_id_hash (ip4_route, NMPlatformIP4Route, {
	/* libnl considers:
	 *   .oo_id_attrs = (ROUTE_ATTR_FAMILY | ROUTE_ATTR_TOS |
	 *                   ROUTE_ATTR_TABLE | ROUTE_ATTR_DST |
	 *                   ROUTE_ATTR_PRIO),
	 */
	hash = (guint) 2569857221;
	hash = hash      + ((guint) obj->ifindex);
	hash = hash * 33 + ((guint) obj->plen);
	hash = hash * 33 + ((guint) obj->metric);
	hash = hash * 33 + ((guint) obj->network);
})
_vt_cmd_plobj_id_hash (ip6_route, NMPlatformIP6Route, {
	hash = (guint) 3999787007;
	hash = hash      + ((guint) obj->ifindex);
	hash = hash * 33 + ((guint) obj->plen);
	hash = hash * 33 + ((guint) obj->metric);
	hash = hash * 33 + _id_hash_ip6_addr (&obj->network);
})

gboolean
nmp_object_is_alive (const NMPObject *obj)

{
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), FALSE);

	return  NMP_OBJECT_GET_CLASS (obj)->cmd_obj_is_alive (obj);
}

static gboolean
_vt_cmd_obj_is_alive_link (const NMPObject *obj)
{
	return obj->_link.netlink.is_in_netlink || obj->_link.udev.device;
}

static gboolean
_vt_cmd_obj_is_alive_ipx_address (const NMPObject *obj)
{
	return TRUE;
}

static gboolean
_vt_cmd_obj_is_alive_ipx_route (const NMPObject *obj)
{
	return obj->ip_route.source != NM_IP_CONFIG_SOURCE_INTERNAL;
}

gboolean
nmp_object_is_visible (const NMPObject *obj)

{
	g_return_val_if_fail (NMP_OBJECT_IS_VALID (obj), FALSE);

	return NMP_OBJECT_GET_CLASS (obj)->cmd_obj_is_visible (obj);
}

static gboolean
_vt_cmd_obj_is_visible_link (const NMPObject *obj)
{
	return obj->_link.netlink.is_in_netlink;
}

static gboolean
_vt_cmd_obj_is_visible_ipx_address (const NMPObject *obj)
{
	return TRUE;
}

static gboolean
_vt_cmd_obj_is_visible_ipx_route (const NMPObject *obj)
{
	NMIPConfigSource source = obj->ip_route.source;

	return source != NM_IP_CONFIG_SOURCE_RTPROT_KERNEL && source != NM_IP_CONFIG_SOURCE_INTERNAL;
}

/******************************************************************/

/**
 * nmp_object_from_nl:
 * @nlo:
 * @id_only: if %TRUE, only fill the id fields of the object and leave the
 *   other fields unset. This is useful to create a needle to lookup a matching
 *   item in the cache.
 *
 * Convert a libnl object to a platform object.
 * Returns: a NMPObject containing @nlo. If @id_only is %TRUE, only the id fields
 *   are defined.
 **/
NMPObject *
nmp_object_from_nl (const struct nl_object *nlo, gboolean id_only)
{
	ObjectType type = _nlo_get_object_type (nlo);
	NMPObject *obj;

	if (type == OBJECT_TYPE_UNKNOWN)
		return NULL;

	obj = nmp_object_new (type, NULL);

	if (!NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_init_from_nl (&obj->object, nlo, id_only)) {
		nmp_object_put (obj);
		return NULL;
	}
	return obj;
}

struct nl_object *
nmp_object_to_nl (NMPlatform *platform, const NMPObject *obj, gboolean id_only)
{
	return NMP_OBJECT_GET_CLASS (obj)->cmd_plobj_to_nl (platform, &obj->object, id_only);
}

/******************************************************************/

gboolean
nmp_cache_id_equal (const NMPCacheId *a, const NMPCacheId *b)
{
	/* just memcmp() the entire id. This is potentially dangerous, because
	 * the struct is not __attribute__((packed)) and not all types have the
	 * same size. It is important, to memset() the entire struct to 0,
	 * not only the relevant fields. */
	return memcmp (a, b, sizeof (NMPCacheId)) == 0;
}

guint
nmp_cache_id_hash (const NMPCacheId *id)
{
	guint hash = 5381;
	guint i;

	for (i = 0; i < sizeof (NMPCacheId); i++)
		hash = ((hash << 5) + hash) + ((char *) id)[i]; /* hash * 33 + c */
	return hash;
}

NMPCacheId *
nmp_cache_id_clone (const NMPCacheId *id)
{
	NMPCacheId *id2;

	id2 = g_slice_new (NMPCacheId);
	memcpy (id2, id, sizeof (NMPCacheId));
	return id2;
}

void
nmp_cache_id_destroy (NMPCacheId *id)
{
	g_slice_free (NMPCacheId, id);
}

/******************************************************************/

NMPCacheId *
nmp_cache_id_init (NMPCacheId *id, NMPCacheIdType id_type)
{
	memset (id, 0, sizeof (NMPCacheId));
	id->_id_type = id_type;
	return id;
}

NMPCacheId *
nmp_cache_id_init_links (NMPCacheId *id, gboolean visible_only)
{
	return nmp_cache_id_init (id, visible_only ? NMP_CACHE_ID_TYPE_LINKS_VISIBLE_ONLY : NMP_CACHE_ID_TYPE_LINKS_ALL);
}

NMPCacheId *
nmp_cache_id_init_addrroute_by_ifindex (NMPCacheId *id, ObjectType obj_type, int ifindex)
{
	nmp_cache_id_init (id, NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX);
	id->addrroute_by_ifindex.obj_type = obj_type;
	id->addrroute_by_ifindex.ifindex = ifindex;
	return id;
}

NMPCacheId *
nmp_cache_id_init_routes_visible (NMPCacheId *id, NMPCacheIdType id_type, gboolean is_v4, int ifindex)
{
	g_return_val_if_fail (NM_IN_SET (id_type, NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ALL, NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT, NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT), NULL);
	nmp_cache_id_init (id, id_type);
	id->routes_visible.is_v4 = !!is_v4;
	id->routes_visible.ifindex = ifindex;
	return id;
}

/******************************************************************/

static gboolean
_vt_cmd_obj_init_cache_id_link (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	switch (id_type) {
	case NMP_CACHE_ID_TYPE_LINKS_ALL:
		*out_id = nmp_cache_id_init_links (id, FALSE);
		return TRUE;
	case NMP_CACHE_ID_TYPE_LINKS_VISIBLE_ONLY:
		if (_vt_cmd_obj_is_visible_link (obj)) {
			*out_id = nmp_cache_id_init_links (id, TRUE);
			return TRUE;
		}
		break;
	default:
		return FALSE;
	}
	*out_id = NULL;
	return TRUE;
}

static gboolean
_vt_cmd_obj_init_cache_id_ip4_address (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	switch (id_type) {
	case NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX:
		if (_vt_cmd_obj_is_visible_ipx_address (obj)) {
			*out_id = nmp_cache_id_init_addrroute_by_ifindex (id, OBJECT_TYPE_IP4_ADDRESS, obj->object.ifindex);
			return TRUE;
		}
		break;
	default:
		return FALSE;
	}
	*out_id = NULL;
	return TRUE;
}

static gboolean
_vt_cmd_obj_init_cache_id_ip6_address (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	switch (id_type) {
	case NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX:
		if (_vt_cmd_obj_is_visible_ipx_address (obj)) {
			*out_id = nmp_cache_id_init_addrroute_by_ifindex (id, OBJECT_TYPE_IP6_ADDRESS, obj->object.ifindex);
			return TRUE;
		}
		break;
	default:
		return FALSE;
	}
	*out_id = NULL;
	return TRUE;
}

static gboolean
_vt_cmd_obj_init_cache_id_ip4_route (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	switch (id_type) {
	case NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX:
		if (_vt_cmd_obj_is_visible_ipx_route (obj)) {
			*out_id = nmp_cache_id_init_addrroute_by_ifindex (id, OBJECT_TYPE_IP4_ROUTE, obj->object.ifindex);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ALL:
		if (_vt_cmd_obj_is_visible_ipx_route (obj)) {
			*out_id = nmp_cache_id_init_routes_visible (id, id_type, TRUE, obj->object.ifindex);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			*out_id = nmp_cache_id_init_routes_visible (id, id_type, TRUE, obj->object.ifindex);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			*out_id = nmp_cache_id_init_routes_visible (id, id_type, TRUE, obj->object.ifindex);
			return TRUE;
		}
		break;
	default:
		return FALSE;
	}
	*out_id = NULL;
	return TRUE;
}

static gboolean
_vt_cmd_obj_init_cache_id_ip6_route (const NMPObject *obj, NMPCacheIdType id_type, NMPCacheId *id, const NMPCacheId **out_id)
{
	switch (id_type) {
	case NMP_CACHE_ID_TYPE_ADDRROUTE_BY_IFINDEX:
		*out_id = nmp_cache_id_init_addrroute_by_ifindex (id, OBJECT_TYPE_IP6_ROUTE, obj->object.ifindex);
		return TRUE;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ALL:
		if (_vt_cmd_obj_is_visible_ipx_route (obj)) {
			*out_id = nmp_cache_id_init_routes_visible (id, id_type, TRUE, obj->object.ifindex);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_NO_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && !NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			*out_id = nmp_cache_id_init_routes_visible (id, id_type, TRUE, obj->object.ifindex);
			return TRUE;
		}
		break;
	case NMP_CACHE_ID_TYPE_ROUTES_VISIBLE_ONLY_DEFAULT:
		if (   _vt_cmd_obj_is_visible_ipx_route (obj)
		    && NM_PLATFORM_IP_ROUTE_IS_DEFAULT (&obj->ip_route)) {
			*out_id = nmp_cache_id_init_routes_visible (id, id_type, TRUE, obj->object.ifindex);
			return TRUE;
		}
		break;
	default:
		return FALSE;
	}
	*out_id = NULL;
	return TRUE;
}

/******************************************************************/

const NMPlatformObject *const *
nmp_cache_lookup_multi (const NMPCache *cache, const NMPCacheId *cache_id, guint *out_len)
{
	return (const NMPlatformObject *const *) nm_multi_index_lookup (cache->idx_multi,
	                                                                (const NMMultiIndexId *) cache_id,
	                                                                out_len);
}

GArray *
nmp_cache_lookup_multi_to_array (const NMPCache *cache, ObjectType obj_type, const NMPCacheId *cache_id)
{
	const NMPClass *klass = nmp_class_from_type (obj_type);
	guint len, i;
	const NMPlatformObject *const *objects;
	GArray *array;

	g_return_val_if_fail (klass, NULL);

	objects = nmp_cache_lookup_multi (cache, cache_id, &len);
	array = g_array_sized_new (FALSE, FALSE, klass->sizeof_public, len);

	for (i = 0; i < len; i++) {
		nm_assert (NMP_OBJECT_GET_CLASS (NMP_OBJECT_UP_CAST (objects[i])) == klass);
		g_array_append_vals (array, objects[i], 1);
	}
	return array;
}

const NMPObject *
nmp_cache_lookup_obj (const NMPCache *cache, const NMPObject *obj)
{
	g_return_val_if_fail (obj, NULL);

	return g_hash_table_lookup (cache->idx_main, obj);
}

const NMPObject *
nmp_cache_lookup_link (const NMPCache *cache, int ifindex)
{
	NMPObject needle;

	return g_hash_table_lookup (cache->idx_main, nmp_object_stackinit_id_link (&needle, ifindex));
}

const NMPlatformLink *
nmp_cache_lookup_link_downcast (const NMPCache *cache, int ifindex)
{
	const NMPObject *obj = nmp_cache_lookup_link (cache, ifindex);

	return obj ? &obj->link : NULL;
}

/******************************************************************/

static void
_nmp_cache_update_cache (NMPCache *cache, NMPObject *obj, gboolean remove)
{
	const NMPClass *klass = NMP_OBJECT_GET_CLASS (obj);
	NMPCacheIdType id_type;

	for (id_type = 0; id_type <= NMP_CACHE_ID_TYPE_MAX; id_type++) {
		NMPCacheId cache_id_storage;
		const NMPCacheId *cache_id;

		if (!klass->cmd_obj_init_cache_id (obj, id_type, &cache_id_storage, &cache_id))
			continue;
		if (!cache_id)
			continue;

		if (remove) {
			if (!nm_multi_index_remove (cache->idx_multi, &cache_id->base, &obj->object))
				g_assert_not_reached ();
		} else {
			if (!nm_multi_index_add (cache->idx_multi, &cache_id->base, &obj->object))
				g_assert_not_reached ();
		}
	}
}

static void
_nmp_cache_update_add (NMPCache *cache, NMPObject *obj)
{
	nm_assert (!obj->is_cached);
	nmp_object_get (obj);
	nm_assert (!nm_multi_index_lookup_first_by_value (cache->idx_multi, obj));
	if (!g_hash_table_add (cache->idx_main, obj))
		g_assert_not_reached ();
	obj->is_cached = TRUE;
	_nmp_cache_update_cache (cache, obj, FALSE);
}

static void
_nmp_cache_update_remove (NMPCache *cache, NMPObject *obj)
{
	nm_assert (obj->is_cached);
	_nmp_cache_update_cache (cache, obj, TRUE);
	obj->is_cached = FALSE;
	if (!g_hash_table_remove (cache->idx_main, obj))
		g_assert_not_reached ();
	nm_assert (!nm_multi_index_lookup_first_by_value (cache->idx_multi, obj));
}

static void
_nmp_cache_update_update (NMPCache *cache, NMPObject *obj, const NMPObject *new, NMPObjectAspects obj_aspect)
{
	const NMPClass *klass = NMP_OBJECT_GET_CLASS (obj);
	NMPCacheIdType id_type;

	nm_assert (klass == NMP_OBJECT_GET_CLASS (new));
	nm_assert (obj->is_cached);
	nm_assert (!new->is_cached);

	for (id_type = 0; id_type <= NMP_CACHE_ID_TYPE_MAX; id_type++) {
		NMPCacheId cache_id_storage_obj, cache_id_storage_new;
		const NMPCacheId *cache_id_obj, *cache_id_new;

		if (!klass->cmd_obj_init_cache_id (obj, id_type, &cache_id_storage_obj, &cache_id_obj))
			continue;
		if (!klass->cmd_obj_init_cache_id (new, id_type, &cache_id_storage_new, &cache_id_new))
			g_assert_not_reached ();
		if (!nm_multi_index_move (cache->idx_multi, (NMMultiIndexId *) cache_id_obj, (NMMultiIndexId *) cache_id_new, &obj->object))
			g_assert_not_reached ();
	}
	nmp_object_copy (obj, new, obj_aspect);
}

NMPCacheOpsType
nmp_cache_remove (NMPCache *cache, const NMPObject *obj, NMPObject **out_obj, gboolean *out_was_visible)
{
	NMPObject *old;

	nm_assert (NMP_OBJECT_IS_VALID (obj));

	old = g_hash_table_lookup (cache->idx_main, obj);
	if (!old) {
		if (out_obj)
			*out_obj = NULL;
		if (out_was_visible)
			*out_was_visible = FALSE;
		return NMP_CACHE_OPS_UNCHANGED;
	}

	if (out_obj)
		*out_obj = nmp_object_get (old);
	if (out_was_visible)
		*out_was_visible = nmp_object_is_visible (old);
	_nmp_cache_update_remove (cache, old);
	return NMP_CACHE_OPS_REMOVED;
}

NMPCacheOpsType
nmp_cache_update (NMPCache *cache, NMPObject *obj, NMPObjectAspects obj_aspect, NMPObject **out_obj, gboolean *out_was_visible)
{
	NMPObject *old;

	nm_assert (NMP_OBJECT_IS_VALID (obj));
	nm_assert (!obj->is_cached);

	old = g_hash_table_lookup (cache->idx_main, obj);

	if (out_obj)
		*out_obj = NULL;
	if (out_was_visible)
		*out_was_visible = FALSE;

	if (!old) {
		if (!nmp_object_is_alive (obj))
			return NMP_CACHE_OPS_UNCHANGED;
		nm_assert (!NMP_OBJECT_IS_STACKINIT (obj));
		if (out_obj)
			*out_obj = nmp_object_get (obj);
		/* leave @out_was_visible at FALSE */
		_nmp_cache_update_add (cache, obj);
		return NMP_CACHE_OPS_ADDED;
	} else if (old == obj) {
		/* updating a cached object inplace is not possible because the object contributes to hash-key
		 * for NMMultiIndex. Modifying an object that is inside NMMultiIndex means that these
		 * keys change.
		 * The problem is, that for a given object NMMultiIndex does not support (efficient)
		 * reverse lookup to get all the NMPCacheIds to which it belongs. If that would be implemented,
		 * it would be possible to implement inplace-update.
		 *
		 * But adding efficient reverse-lookup to NMMultiIndex adds some overhead for an uncommon(?) usage
		 * pattern. Probably it's more efficient just to forbid it and require the user to:
		 *   - clone the object, modify the clone, and nmp_cache_update() the clone.
		 *   - remove the object, modify the object, add again with nmp_cache_update()
		 */
		g_assert_not_reached ();
	} else {
		nm_assert (old->is_cached);

		if (out_obj)
			*out_obj = nmp_object_get (old);
		if (out_was_visible)
			*out_was_visible = nmp_object_is_visible (old);

		if (nmp_object_equal (old, obj, obj_aspect)) {
			/* don't set @out_obj and @out_was_visible. They have no meaning if the object didn't change. */
			return NMP_CACHE_OPS_UNCHANGED;
		}

		if (NMP_OBJECT_GET_CLASS (old)->has_other_aspects) {
			auto_nmp_obj NMPObject *obj_merged = NULL;
			/* Links need some special handling, because they have more then
			 * one aspect.
			 *
			 * for _nmp_cache_update_update() we need the (entire) old and new object.
			 * @obj contains only certain aspects, so we have to merge first @old
			 * and @obj to @obj_merged. */

			obj_merged = nmp_object_clone (old, FALSE);

			/* merge @obj into @obj_merged */
			nmp_object_copy (obj_merged, obj, obj_aspect);

			if (!nmp_object_is_alive (obj_merged)) {
				/* the update would make @old invalid. Remove it. */
				_nmp_cache_update_remove (cache, old);
				return NMP_CACHE_OPS_REMOVED;
			}
		} else {
			if (!nmp_object_is_alive (obj)) {
				_nmp_cache_update_remove (cache, old);
				return NMP_CACHE_OPS_REMOVED;
			}
		}

		_nmp_cache_update_update (cache, old, obj, obj_aspect);
		return NMP_CACHE_OPS_UPDATED;
	}
}

/******************************************************************/

NMPCache *
nmp_cache_new ()
{
	NMPCache *cache = g_new (NMPCache, 1);

	cache->idx_main = g_hash_table_new_full ((GHashFunc) nmp_object_id_hash,
	                                         (GEqualFunc) nmp_object_id_equal,
	                                         (GDestroyNotify) nmp_object_put,
	                                         NULL);
	cache->idx_multi = nm_multi_index_new ((NMMultiIndexFuncHash) nmp_cache_id_hash,
	                                       (NMMultiIndexFuncEqual) nmp_cache_id_equal,
	                                       (NMMultiIndexFuncClone) nmp_cache_id_clone,
	                                       (NMMultiIndexFuncDestroy) nmp_cache_id_destroy);
	return cache;
}

void
nmp_cache_free (NMPCache *cache)
{
	while (g_hash_table_size (cache->idx_main) > 0) {
		GHashTableIter iter;
		NMPObject *obj;

		g_hash_table_iter_init (&iter, cache->idx_main);
		g_hash_table_iter_next (&iter, (gpointer *) &obj, NULL);

		_nmp_cache_update_remove (cache, obj);
	}

	g_hash_table_unref (cache->idx_main);
	nm_multi_index_free (cache->idx_multi);

	g_free (cache);
}

/******************************************************************/

static const NMPClass nmp_classes[OBJECT_TYPE_MAX] = {
	[OBJECT_TYPE_LINK - 1] = {
		.type                               = OBJECT_TYPE_LINK,
		.sizeof_data                        = sizeof (NMPObjectLink),
		.sizeof_public                      = sizeof (NMPlatformLink),
		.has_other_aspects                  = TRUE,
		.nl_type                            = "route/link",
		.signal_type                        = NM_PLATFORM_SIGNAL_LINK_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_link,
		.cmd_obj_equal                      = _vt_cmd_obj_equal_link,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_link,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_link,
		.cmd_obj_dispose                    = _vt_cmd_obj_dispose_link,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_link,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_link,
		.cmd_plobj_init_from_nl             = _nmp_vt_cmd_plobj_init_from_nl_link,
		.cmd_plobj_to_nl                    = _nmp_vt_cmd_plobj_to_nl_link,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_link,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_link,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_link,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj)) nm_platform_link_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_link_cmp,
	},
	[OBJECT_TYPE_IP4_ADDRESS - 1] = {
		.type                               = OBJECT_TYPE_IP4_ADDRESS,
		.sizeof_data                        = sizeof (NMPObjectIP4Address),
		.sizeof_public                      = sizeof (NMPlatformIP4Address),
		.nl_type                            = "route/addr",
		.signal_type                        = NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ip4_address,
		.cmd_obj_equal                      = _vt_cmd_obj_equal_plain,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_plain,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip4_address,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_address,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_address,
		.cmd_plobj_init_from_nl             = _nmp_vt_cmd_plobj_init_from_nl_ip4_address,
		.cmd_plobj_to_nl                    = _nmp_vt_cmd_plobj_to_nl_ip4_address,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip4_address,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip4_address,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip4_address,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj)) nm_platform_ip4_address_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip4_address_cmp,
	},
	[OBJECT_TYPE_IP6_ADDRESS - 1] = {
		.type                               = OBJECT_TYPE_IP6_ADDRESS,
		.sizeof_data                        = sizeof (NMPObjectIP6Address),
		.sizeof_public                      = sizeof (NMPlatformIP6Address),
		.nl_type                            = "route/addr",
		.signal_type                        = NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ip6_address,
		.cmd_obj_equal                      = _vt_cmd_obj_equal_plain,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_plain,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip6_address,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_address,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_address,
		.cmd_plobj_init_from_nl             = _nmp_vt_cmd_plobj_init_from_nl_ip6_address,
		.cmd_plobj_to_nl                    = _nmp_vt_cmd_plobj_to_nl_ip6_address,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip6_address,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip6_address,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip6_address,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj)) nm_platform_ip6_address_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip6_address_cmp
	},
	[OBJECT_TYPE_IP4_ROUTE - 1] = {
		.type                               = OBJECT_TYPE_IP4_ROUTE,
		.sizeof_data                        = sizeof (NMPObjectIP4Route),
		.sizeof_public                      = sizeof (NMPlatformIP4Route),
		.nl_type                            = "route/route",
		.signal_type                        = NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ip4_route,
		.cmd_obj_equal                      = _vt_cmd_obj_equal_plain,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_plain,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip4_route,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_route,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_route,
		.cmd_plobj_init_from_nl             = _nmp_vt_cmd_plobj_init_from_nl_ip4_route,
		.cmd_plobj_to_nl                    = _nmp_vt_cmd_plobj_to_nl_ip4_route,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip4_route,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip4_route,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip4_route,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj)) nm_platform_ip4_route_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip4_route_cmp,
	},
	[OBJECT_TYPE_IP6_ROUTE - 1] = {
		.type                               = OBJECT_TYPE_IP6_ROUTE,
		.sizeof_data                        = sizeof (NMPObjectIP6Route),
		.sizeof_public                      = sizeof (NMPlatformIP6Route),
		.nl_type                            = "route/route",
		.signal_type                        = NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
		.cmd_obj_init_cache_id              = _vt_cmd_obj_init_cache_id_ip6_route,
		.cmd_obj_equal                      = _vt_cmd_obj_equal_plain,
		.cmd_obj_copy                       = _vt_cmd_obj_copy_plain,
		.cmd_obj_stackinit_id               = _vt_cmd_obj_stackinit_id_ip6_route,
		.cmd_obj_is_alive                   = _vt_cmd_obj_is_alive_ipx_route,
		.cmd_obj_is_visible                 = _vt_cmd_obj_is_visible_ipx_route,
		.cmd_plobj_init_from_nl             = _nmp_vt_cmd_plobj_init_from_nl_ip6_route,
		.cmd_plobj_to_nl                    = _nmp_vt_cmd_plobj_to_nl_ip6_route,
		.cmd_plobj_id_copy                  = _vt_cmd_plobj_id_copy_ip6_route,
		.cmd_plobj_id_equal                 = _vt_cmd_plobj_id_equal_ip6_route,
		.cmd_plobj_id_hash                  = _vt_cmd_plobj_id_hash_ip6_route,
		.cmd_plobj_to_string                = (const char *(*) (const NMPlatformObject *obj)) nm_platform_ip6_route_to_string,
		.cmd_plobj_cmp                      = (int (*) (const NMPlatformObject *obj1, const NMPlatformObject *obj2)) nm_platform_ip6_route_cmp,
	},
};


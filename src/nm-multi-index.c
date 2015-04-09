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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "config.h"

#include "nm-multi-index.h"

#include "nm-glib-compat.h"
#include "nm-utils-internal.h"


struct NMMultiIndex {
	NMMultiIndexFuncEqual equal_fcn;
	NMMultiIndexFuncClone clone_fcn;
	GHashTable *hash;
};

typedef gint idx_t;

/******************************************************************************************/

static idx_t
_binary_search (GPtrArray *array, gconstpointer value)
{
	idx_t imin, imid, imax;

	imin = 0;
	imax = (idx_t) array->len - 2; /* the last index is NULL, hence start at -2. */
	while (imin <= imax) {
		imid = imin + ((imax - imin) / 2);

		if (value < array->pdata[imid])
			imax = imid - 1;
		else if (array->pdata[imid] < value)
			imin = imid + 1;
		else
			return imid;
	}
	/* if not found, @imin is the insertion point. Return ~imin (which would be negative). */
	nm_assert (   imin >= 0
	           && imin <= array->len - 1
	           && (imin == 0 || array->pdata[imin - 1] < value)
	           && (imin == array->len - 1 || array->pdata[imin] > value));
	return ~imin;
}

/**
 * nm_multi_index_lookup():
 * @index:
 * @id:
 * @out_len: (allow-none): output the number of values
 *   that are returned.
 *
 * Returns: (transfer-none): %NULL if there are no values
 *   or a %NULL terminated array of pointers. The pointers
 *   are sorted ascendingly.
 */
void *const*
nm_multi_index_lookup (const NMMultiIndex *index,
                       const NMMultiIndexId *id,
                       guint *out_len)
{
	GPtrArray *array;

	g_return_val_if_fail (index, NULL);
	g_return_val_if_fail (id, NULL);

	array = g_hash_table_lookup (index->hash, id);
	nm_assert (!array || array->len >= 2);
	if (out_len)
		*out_len = array ? array->len - 1 : 0;
	return array ? (void **)array->pdata : NULL;
}

gboolean
nm_multi_index_contains (const NMMultiIndex *index,
                         const NMMultiIndexId *id,
                         gconstpointer value)
{
	GPtrArray *array;

	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (id, FALSE);
	g_return_val_if_fail (value, FALSE);

	array = g_hash_table_lookup (index->hash, id);
	return    array
	       && _binary_search (array, value) >= 0;
}

const NMMultiIndexId *
nm_multi_index_lookup_first_by_value (const NMMultiIndex *index,
                                      gconstpointer value)
{
	GHashTableIter iter;
	const NMMultiIndexId *id;
	GPtrArray *array;

	g_return_val_if_fail (index, NULL);
	g_return_val_if_fail (value, NULL);

	/* reverse-lookup needs to iterate over all hash tables and then
	 * do binary search. It should still be fairly quick, if the number
	 * of hash tables is small.
	 * There is no O(1) reverse lookup implemented, because this access
	 * pattern is not what NMMultiIndex is here for.
	 * You are supposed to use NMMultiIndex by always knowing which @id
	 * a @value has.
	 */

	g_hash_table_iter_init (&iter, index->hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &array)) {
		if (_binary_search (array, value) >= 0)
			return id;
	}
	return NULL;
}

void
nm_multi_index_foreach (const NMMultiIndex *index,
                        gconstpointer value,
                        NMMultiIndexFuncForeach foreach_func,
                        gpointer user_data)
{
	GHashTableIter iter;
	const NMMultiIndexId *id;
	GPtrArray *array;

	g_return_if_fail (index);
	g_return_if_fail (foreach_func);

	g_hash_table_iter_init (&iter, index->hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &array)) {
		nm_assert (array->len >= 2);

		if (   value
		    && _binary_search (array, value) < 0)
			continue;

		if (!foreach_func (id, array->pdata, array->len - 1, user_data))
			return;
	}
}

void
nm_multi_index_iter_init (NMMultiIndexIter *iter,
                          const NMMultiIndex *index,
                          gconstpointer value)
{
	g_return_if_fail (index);
	g_return_if_fail (iter);

	g_hash_table_iter_init (&iter->_iter, index->hash);
	iter->_index = index;
	iter->_value = value;
}

gboolean
nm_multi_index_iter_next (NMMultiIndexIter *iter,
                          const NMMultiIndexId **out_id,
                          void *const**out_values,
                          guint *out_len)
{
	const NMMultiIndexId *id;
	GPtrArray *array;

	g_return_val_if_fail (iter, FALSE);

	while (g_hash_table_iter_next (&iter->_iter, (gpointer *) &id, (gpointer *) &array)) {
		if (   !iter->_value
		    || _binary_search (array, iter->_value) >= 0) {
			if (out_id)
				*out_id = id;
			if (out_values)
				*out_values = array->pdata;
			if (out_len)
				*out_len = array->len - 1;
			return TRUE;
		}
	}
	return FALSE;
}

/******************************************************************************************/

static gboolean
_do_add (NMMultiIndex *index,
         const NMMultiIndexId *id,
         gconstpointer value)
{
	GPtrArray *array;

	array = g_hash_table_lookup (index->hash, id);
	if (!array) {
		NMMultiIndexId *id_new;

		array = g_ptr_array_sized_new (2);
		g_ptr_array_add (array, (gpointer) value);
		g_ptr_array_add (array, NULL);

		/* Contrary to GHashTable, we don't take ownership of the @id that was
		 * provided to nm_multi_index_add(). Instead we clone it via @clone_fcn
		 * when needed.
		 *
		 * The reason is, that we expect in most cases that there exists
		 * already a @id so that we don't need ownership of it (or clone it).
		 * By doing this, the caller can pass a stack allocated @id or
		 * reuse the @id for other insertions.
		 */
		id_new = index->clone_fcn (id);
		if (!id_new)
			g_return_val_if_reached (FALSE);

		g_hash_table_insert (index->hash, id_new, array);
	} else {
		idx_t i = _binary_search (array, value);

		if (i >= 0)
			return FALSE;

		/* idx_t is gint, so we cannot add more then G_MAXINT values. */
		if (array->len + 1 >= (guint) G_MAXINT)
			g_return_val_if_reached (FALSE);
		g_ptr_array_insert (array, ~i, (gpointer) value);
	}
	return TRUE;
}

static gboolean
_do_remove (NMMultiIndex *index,
            const NMMultiIndexId *id,
            gconstpointer value)
{
	GPtrArray *array;

	array = g_hash_table_lookup (index->hash, id);
	if (!array)
		return FALSE;

	if (array->len <= 2) {
		nm_assert (array->len == 2 && array->pdata[1] == NULL);
		if (array->pdata[0] != value)
			return FALSE;
		g_hash_table_remove (index->hash, id);
	} else {
		idx_t i = _binary_search (array, value);

		if (i < 0)
			return FALSE;
		g_ptr_array_remove_index (array, i);
	}
	return TRUE;
}

gboolean
nm_multi_index_add (NMMultiIndex *index,
                    const NMMultiIndexId *id,
                    gconstpointer value)
{
	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (value, FALSE);

	if (!id)
		g_return_val_if_reached (FALSE);
	return _do_add (index, id, value);
}

gboolean
nm_multi_index_remove (NMMultiIndex *index,
                       const NMMultiIndexId *id,
                       gconstpointer value)
{
	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (value, FALSE);

	if (!id)
		g_return_val_if_reached (FALSE);
	return _do_remove (index, id, value);
}

/**
 * nm_multi_index_move:
 * @index:
 * @id_old: (allow-none): remove @value at @id_old
 * @id_new: (allow-none): add @value under @id_new
 * @value: the value to add
 *
 * Similar to a remove(), followed by an add(). The difference
 * is, that we allow %NULL for both @id_old and @id_new.
 * And the return value undicates whether @value was successfully
 * removed and added.
 *
 * Returns: %TRUE, if the value was removed from @id_old and added
 *   as %id_new. %FALSE could mean, that @value was not added as @id_old
 *   or that @value was already part of @id_new. */
gboolean
nm_multi_index_move (NMMultiIndex *index,
                     const NMMultiIndexId *id_old,
                     const NMMultiIndexId *id_new,
                     gconstpointer value)
{
	g_return_val_if_fail (index, FALSE);
	g_return_val_if_fail (value, FALSE);

	if (!id_old && !id_new) {
		/* nothing to do, @value was and is not in @index. */
		return TRUE;
	} if (!id_old) {
		/* add @value to @index with @id_new */
		return _do_add (index, id_new, value);
	} else if (!id_new) {
		/* remove @value from @index with @id_old */
		return _do_remove (index, id_old, value);
	} else if (index->equal_fcn (id_old, id_new)) {
		if (_do_add (index, id_new, value)) {
			/* we would expect, that @value is already in @index,
			 * Return %FALSE, if it wasn't. */
			return FALSE;
		}
		return TRUE;
	} else {
		gboolean did_remove;

		did_remove = _do_remove (index, id_old, value);
		return _do_add (index, id_new, value) && did_remove;
	}
}

/******************************************************************************************/

guint
nm_multi_index_get_num_groups (const NMMultiIndex *index)
{
	g_return_val_if_fail (index, 0);
	return g_hash_table_size (index->hash);
}

NMMultiIndex *
nm_multi_index_new (NMMultiIndexFuncHash hash_fcn,
                    NMMultiIndexFuncEqual equal_fcn,
                    NMMultiIndexFuncClone clone_fcn,
                    NMMultiIndexFuncDestroy destroy_fcn)
{
	NMMultiIndex *index;

	g_return_val_if_fail (hash_fcn, NULL);
	g_return_val_if_fail (equal_fcn, NULL);
	g_return_val_if_fail (clone_fcn, NULL);
	g_return_val_if_fail (destroy_fcn, NULL);

	index = g_new (NMMultiIndex, 1);
	index->equal_fcn = equal_fcn;
	index->clone_fcn = clone_fcn;

	index->hash = g_hash_table_new_full ((GHashFunc) hash_fcn,
	                                     (GEqualFunc) equal_fcn,
	                                     (GDestroyNotify) destroy_fcn,
	                                     (GDestroyNotify) g_ptr_array_unref);
	return index;
}

void
nm_multi_index_free (NMMultiIndex *index)
{
	g_return_if_fail (index);
	g_hash_table_unref (index->hash);
	g_free (index);
}


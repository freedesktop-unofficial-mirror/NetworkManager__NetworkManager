/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2012 Red Hat, Inc.
 */

#ifndef __NM_OBJECT_H__
#define __NM_OBJECT_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <gio/gio.h>

#include <nm-version.h>

G_BEGIN_DECLS

#define NM_TYPE_OBJECT            (nm_object_get_type ())
#define NM_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OBJECT, NMObject))
#define NM_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OBJECT, NMObjectClass))
#define NM_IS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OBJECT))
#define NM_IS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OBJECT))
#define NM_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OBJECT, NMObjectClass))

/**
 * NMObjectError:
 * @NM_OBJECT_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_OBJECT_ERROR_OBJECT_CREATION_FAILURE: an error ocured while creating an #NMObject
 *
 * Describes errors that may result from operations involving a #NMObject.
 *
 **/
typedef enum {
	NM_OBJECT_ERROR_UNKNOWN = 0,
	NM_OBJECT_ERROR_OBJECT_CREATION_FAILURE,
} NMObjectError;

#define NM_OBJECT_ERROR nm_object_error_quark ()
GQuark nm_object_error_quark (void);

#define NM_OBJECT_PATH "path"
#define NM_OBJECT_DBUS_CONNECTION "dbus-connection"

typedef struct {
	GObject parent;
} NMObject;

typedef struct {
	GObjectClass parent;

	/* Signals */
	/* The "object-creation-failed" signal is PRIVATE for libnm and
	 * is not meant for any external usage.  It indicates that an error
	 * occured during creation of an object.
	 */
	void (*object_creation_failed) (NMObject *master_object,
	                                GError *error,
	                                char *failed_path);

	/* Methods */
	void (*init_dbus) (NMObject *object);

	/*< private >*/
	gpointer padding[8];
} NMObjectClass;

GType nm_object_get_type (void);

const char      *nm_object_get_path            (NMObject *object);

G_END_DECLS

#endif /* __NM_OBJECT_H__ */

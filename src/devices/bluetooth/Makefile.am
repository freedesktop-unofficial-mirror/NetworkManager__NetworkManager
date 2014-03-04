include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src/devices \
	-I${top_srcdir}/src/settings \
	-I${top_srcdir}/src/platform \
	-I${top_srcdir}/src/devices/wwan \
	-I${top_builddir}/include \
	-I${top_srcdir}/include \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-util \
	$(DBUS_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(GUDEV_CFLAGS)

GLIB_GENERATED = nm-bt-enum-types.h nm-bt-enum-types.c
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM
nm_bt_enum_types_sources = $(srcdir)/nm-device-bt.h

nm-device-bt-glue.h: $(top_srcdir)/introspection/nm-device-bt.xml
	dbus-binding-tool --prefix=nm_device_bt --mode=glib-server --output=$@ $<

BUILT_SOURCES = $(GLIB_GENERATED) nm-device-bt-glue.h

pkglib_LTLIBRARIES = libnm-device-plugin-bt.la

libnm_device_plugin_bt_la_SOURCES = \
	nm-bluez-manager.c \
	nm-bluez-manager.h \
	nm-bluez-common.h \
	nm-bluez-device.c \
	nm-bluez-device.h \
	nm-bluez4-adapter.c \
	nm-bluez4-adapter.h \
	nm-bluez4-manager.c \
	nm-bluez4-manager.h \
	nm-bluez5-manager.c \
	nm-bluez5-manager.h \
	\
	nm-device-bt.c \
	nm-device-bt.h \
	\
	$(BUILT_SOURCES)

libnm_device_plugin_bt_la_LDFLAGS = -module -avoid-version
libnm_device_plugin_bt_la_LIBADD = \
	$(top_builddir)/src/devices/wwan/libnm-wwan.la \
	$(DBUS_LIBS) \
	$(GUDEV_LIBS)

CLEANFILES = $(BUILT_SOURCES)

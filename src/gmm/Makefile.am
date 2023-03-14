# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=0:0:0

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

lib_LTLIBRARIES = \
	libosmo-gprs-gmm.la \
	$(NULL)

libosmo_gprs_gmm_la_SOURCES = \
	gmm.c \
	gmm_prim.c \
	misc.c \
	$(NULL)

libosmo_gprs_gmm_la_LDFLAGS = \
	-export-symbols-regex '^osmo_' \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_gprs_gmm_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	-lm \
	$(NULL)

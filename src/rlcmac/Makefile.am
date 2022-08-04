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
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

lib_LTLIBRARIES = \
	libosmo-gprs-rlcmac.la \
	$(NULL)

libosmo_gprs_rlcmac_la_SOURCES = \
	gprs_rlcmac.c \
	$(NULL)

libosmo_gprs_rlcmac_la_LDFLAGS = \
	-export-symbols-regex '^osmo_' \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_gprs_rlcmac_la_LIBADD = \
	$(top_builddir)/src/csn1/libosmo-csn1.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

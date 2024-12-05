# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=1:0:0

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

lib_LTLIBRARIES = \
	libosmo-gprs-sndcp.la \
	$(NULL)

libosmo_gprs_sndcp_la_SOURCES = \
	slhc.c \
	sndcp.c \
	sndcp_prim.c \
	sndcp_comp.c \
	sndcp_dcomp.c \
	sndcp_pcomp.c \
	sndcp_xid.c \
	misc.c \
	v42bis.c \
	$(NULL)

libosmo_gprs_sndcp_la_LDFLAGS = \
	-export-symbols-regex '^osmo_' \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_gprs_sndcp_la_LIBADD = \
	$(top_builddir)/src/common/libosmo-gprs-common.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	-lm \
	$(NULL)

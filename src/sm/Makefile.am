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
	libosmo-gprs-sm.la \
	$(NULL)

libosmo_gprs_sm_la_SOURCES = \
	sm.c \
	sm_ms_fsm.c \
	sm_pdu.c \
	sm_prim.c \
	misc.c \
	$(NULL)

libosmo_gprs_sm_la_LDFLAGS = \
	-export-symbols-regex '^osmo_' \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_gprs_sm_la_LIBADD = \
	$(top_builddir)/src/gmm/libosmo-gprs-gmm.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	-lm \
	$(NULL)

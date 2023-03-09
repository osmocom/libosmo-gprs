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
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

lib_LTLIBRARIES = \
	libosmo-gprs-llc.la \
	$(NULL)

libosmo_gprs_llc_la_SOURCES = \
	crc24.c \
	llc.c \
	llc_bssgp.c \
	llc_ll.c \
	llc_llgmm.c \
	llc_grr.c \
	llc_pdu.c \
	llc_prim.c \
	llc_xid.c \
	misc.c \
	$(NULL)

libosmo_gprs_llc_la_LDFLAGS = \
	-export-symbols-regex '^osmo_' \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_gprs_llc_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

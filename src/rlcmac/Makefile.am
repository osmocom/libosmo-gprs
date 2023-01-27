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

AM_LDFLAGS = \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

lib_LTLIBRARIES = \
	libosmo-gprs-rlcmac.la \
	$(NULL)

libosmo_gprs_rlcmac_la_SOURCES = \
	csn1_ts_24_008.c \
	csn1_ts_44_018.c \
	csn1_ts_44_060.c \
	codel.c \
	gre.c \
	llc_queue.c \
	rlcmac.c \
	rlcmac_enc.c \
	rlcmac_prim.c \
	sched.c \
	tbf.c \
	tbf_ul.c \
	tbf_ul_fsm.c \
	tbf_ul_ass_fsm.c \
	ts_44_060.c \
	ts_44_064.c \
	misc.c \
	$(NULL)

libosmo_gprs_rlcmac_la_LDFLAGS = \
	-export-symbols-regex '^osmo_' \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_gprs_rlcmac_la_LIBADD = \
	$(top_builddir)/src/csn1/libosmo-csn1.la \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

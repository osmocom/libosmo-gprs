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
	codel.c \
	coding_scheme.c \
	csn1_ts_24_008.c \
	csn1_ts_44_018.c \
	csn1_ts_44_060.c \
	gre.c \
	pdch_ul_controller.c \
	llc_queue.c \
	rlc_window.c \
	rlc_window_dl.c \
	rlc_window_ul.c \
	rlc.c \
	rlcmac.c \
	rlcmac_dec.c \
	rlcmac_enc.c \
	rlcmac_prim.c \
	sched.c \
	tbf.c \
	tbf_dl.c \
	tbf_dl_fsm.c \
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

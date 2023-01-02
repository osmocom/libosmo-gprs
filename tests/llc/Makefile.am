AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	-I$(top_srcdir)/include/ \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

check_PROGRAMS = \
	llc_test \
	llc_prim_test \
	pdu_codec_test \
	xid_codec_test \
	$(NULL)

EXTRA_DIST = \
	llc_test.err \
	llc_test.ok \
	llc_prim_test.err \
	llc_prim_test.ok \
	pdu_codec_test.ok \
	pdu_codec_test.err \
	xid_codec_test.ok \
	xid_codec_test.err \
	$(NULL)

llc_test_SOURCES = llc_test.c
llc_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(top_builddir)/src/llc/libosmo-gprs-llc.la \
	$(NULL)

llc_prim_test_SOURCES = llc_prim_test.c
llc_prim_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(top_builddir)/src/llc/libosmo-gprs-llc.la \
	$(NULL)

pdu_codec_test_SOURCES = pdu_codec_test.c
# libosmo-gprs-llc.a is used below to access non-exported private symbols used in the test:
pdu_codec_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(top_builddir)/src/llc/.libs/libosmo-gprs-llc.a \
	$(NULL)

xid_codec_test_SOURCES = xid_codec_test.c
# libosmo-gprs-llc.a is used below to access non-exported private symbols used in the test:
xid_codec_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(top_builddir)/src/llc/.libs/libosmo-gprs-llc.a \
	$(NULL)

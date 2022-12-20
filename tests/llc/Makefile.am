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
	pdu_codec_test \
	$(NULL)

EXTRA_DIST = \
	pdu_codec_test.ok \
	pdu_codec_test.err \
	$(NULL)

pdu_codec_test_SOURCES = pdu_codec_test.c
pdu_codec_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(top_builddir)/src/llc/libosmo-gprs-llc.la \
	$(NULL)

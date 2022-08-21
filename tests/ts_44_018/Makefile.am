AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	-I$(top_srcdir)/include/ \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

check_PROGRAMS = \
	ts_44_018_test \
	$(NULL)

EXTRA_DIST = \
	ts_44_018_test.ok \
	ts_44_018_test.err \
	$(NULL)

ts_44_018_test_SOURCES = ts_44_018_test.c
ts_44_018_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(top_builddir)/src/csn1/libosmo-csn1.la \
	$(top_builddir)/src/rlcmac/libosmo-gprs-rlcmac.la \
	$(NULL)

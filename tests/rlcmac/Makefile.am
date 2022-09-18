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
	ts_44_060_test \
	$(NULL)

EXTRA_DIST = \
	ts_44_018_test.ok \
	ts_44_018_test.err \
	ts_44_060_test.ok \
	ts_44_060_test.err \
	$(NULL)

# Common LDADD entries
LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(top_builddir)/src/csn1/libosmo-csn1.la \
	$(top_builddir)/src/rlcmac/libosmo-gprs-rlcmac.la \
	$(NULL)

ts_44_018_test_SOURCES = ts_44_018_test.c
ts_44_018_test_LDADD = $(LDADD)

ts_44_060_test_SOURCES = ts_44_060_test.c
ts_44_060_test_LDADD = $(LDADD)

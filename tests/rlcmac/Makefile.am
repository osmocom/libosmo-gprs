AM_CPPFLAGS = \
	-I$(top_srcdir)/include/ \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

check_PROGRAMS = \
	csn1_ts_44_018_test \
	csn1_ts_44_060_test \
	rlcmac_prim_test \
	$(NULL)

EXTRA_DIST = \
	csn1_ts_44_018_test.ok \
	csn1_ts_44_018_test.err \
	csn1_ts_44_060_test.ok \
	csn1_ts_44_060_test.err \
	rlcmac_prim_test.ok \
	rlcmac_prim_test.err \
	$(NULL)

# Common LDADD entries
# libosmo-gprs-rlcmac.a is used below to access non-exported private symbols used in the test:
LDADD = \
	$(top_builddir)/src/rlcmac/.libs/libosmo-gprs-rlcmac.a \
	$(top_builddir)/src/csn1/libosmo-csn1.la \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

csn1_ts_44_018_test_SOURCES = csn1_ts_44_018_test.c
csn1_ts_44_018_test_LDADD = $(LDADD)

csn1_ts_44_060_test_SOURCES = csn1_ts_44_060_test.c
csn1_ts_44_060_test_LDADD = $(LDADD)

rlcmac_prim_test_SOURCES = rlcmac_prim_test.c
rlcmac_prim_test_LDADD = $(LDADD)

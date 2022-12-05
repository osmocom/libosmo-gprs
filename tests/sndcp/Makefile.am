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
	sndcp_prim_test \
	sndcp_xid_test \
	slhc_test \
	$(NULL)

EXTRA_DIST = \
	sndcp_prim_test.err \
	sndcp_prim_test.ok \
	sndcp_xid_test.ok \
	slhc_test.ok \
	$(NULL)

sndcp_prim_test_SOURCES = sndcp_prim_test.c
# libosmo-gprs-llc.a is used below to access non-exported private symbols used in the test:
sndcp_prim_test_LDADD = \
	$(top_builddir)/src/sndcp/libosmo-gprs-sndcp.la \
	$(top_builddir)/src/llc/.libs/libosmo-gprs-llc.a \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	-lrt -lm \
	$(NULL)

sndcp_xid_test_SOURCES = sndcp_xid_test.c
# libosmo-gprs-sndcp.a is used below to access non-exported private symbols used in the test:
sndcp_xid_test_LDADD = \
	$(top_builddir)/src/sndcp/.libs/libosmo-gprs-sndcp.a \
	$(top_builddir)/src/llc/libosmo-gprs-llc.la \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	-lrt -lm \
	$(NULL)

slhc_test_SOURCES = slhc_test.c
# libosmo-gprs-sndcp.a is used below to access non-exported private symbols used in the test:
slhc_test_LDADD = \
	$(top_builddir)/src/sndcp/.libs/libosmo-gprs-sndcp.a \
	$(top_builddir)/src/llc/libosmo-gprs-llc.la \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	-lrt -lm \
	$(NULL)

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
	sm_prim_test \
	$(NULL)

EXTRA_DIST = \
	sm_prim_test.err \
	sm_prim_test.ok \
	$(NULL)

# libosmo-gprs-gmm.a is used below to access non-exported private symbols used in the test:
# libosmo-gprs-gmm.a requires libosmo-gprs-llc.la
sm_prim_test_SOURCES = sm_prim_test.c
sm_prim_test_LDADD = \
	$(top_builddir)/src/sm/libosmo-gprs-sm.la \
	$(top_builddir)/src/gmm/.libs/libosmo-gprs-gmm.a \
	$(top_builddir)/src/llc/.libs/libosmo-gprs-llc.la \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

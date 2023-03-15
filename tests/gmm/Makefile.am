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
	gmm_prim_test \
	$(NULL)

EXTRA_DIST = \
	gmm_prim_test.err \
	gmm_prim_test.ok \
	$(NULL)

# libosmo-gprs-llc.a is used below to access non-exported private symbols used in the test:
gmm_prim_test_SOURCES = gmm_prim_test.c
gmm_prim_test_LDADD = \
	$(top_builddir)/src/gmm/libosmo-gprs-gmm.la \
	$(top_builddir)/src/llc/.libs/libosmo-gprs-llc.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

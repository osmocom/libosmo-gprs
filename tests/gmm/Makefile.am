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
	gmm_misc_test \
	gmm_prim_test \
	$(NULL)

EXTRA_DIST = \
	gmm_misc_test.err \
	gmm_misc_test.ok \
	gmm_prim_test.err \
	gmm_prim_test.ok \
	$(NULL)

# libosmo-gprs-gmm.a is used below to access non-exported private symbols used in the test:
gmm_misc_test_SOURCES = gmm_misc_test.c
gmm_misc_test_LDADD = \
	$(top_builddir)/src/gmm/.libs/libosmo-gprs-gmm.a \
	$(top_builddir)/src/llc/.libs/libosmo-gprs-llc.a \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

gmm_misc_test_LDFLAGS = \
	-no-install \
	$(NULL)

# libosmo-gprs-llc.a is used below to access non-exported private symbols used in the test:
gmm_prim_test_SOURCES = gmm_prim_test.c
gmm_prim_test_LDADD = \
	$(top_builddir)/src/gmm/libosmo-gprs-gmm.la \
	$(top_builddir)/src/llc/.libs/libosmo-gprs-llc.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

gmm_prim_test_LDFLAGS = \
	-Wl,--wrap=osmo_get_rand_id \
	-no-install \
	$(NULL)

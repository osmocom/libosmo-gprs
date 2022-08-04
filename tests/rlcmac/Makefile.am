AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	-I$(top_srcdir)/include/ \
	$(NULL)

AM_LDFLAGS = \
	-no-install \
	$(NULL)

check_PROGRAMS = \
	RLCMACTest \
	$(NULL)

EXTRA_DIST = \
	rlcmac/RLCMACTest.ok \
	rlcmac/RLCMACTest.err \
	$(NULL)

RLCMACTest_SOURCES = RLCMACTest.c
RLCMACTest_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(top_builddir)/src/csn1/libosmo-csn1.la \
	$(top_builddir)/src/rlcmac/libosmo-gprs-rlcmac.la \
	$(NULL)

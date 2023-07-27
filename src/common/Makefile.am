AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

noinst_LTLIBRARIES = \
	libosmo-gprs-common.la \
	$(NULL)

libosmo_gprs_common_la_SOURCES = \
	qos.c \
	$(NULL)

noinst_HEADERS = \
	qos.h \
	$(NULL)
